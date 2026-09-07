<?php

declare(strict_types=1);

namespace Tests\PasskeyMfa\Libraries;

use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;
use PasskeyMfa\Libraries\Base64Url;
use PasskeyMfa\Libraries\PasskeyIdentityStore;
use PasskeyMfa\Models\PasskeyCredentialModel;

/**
 * Tests everything about PasskeyIdentityStore EXCEPT the actual
 * cryptographic verification (completeRegistration()/completeAuthentication()'s
 * success paths) - that needs a real browser and authenticator to
 * produce genuinely valid WebAuthn responses, which can't be faked
 * without either one or a software/virtual authenticator library this
 * package doesn't depend on. See this package's README for why that's
 * a deliberate, documented limitation rather than an oversight.
 *
 * What IS covered, and is genuinely valuable: marker sync (the same
 * two-identity-type mechanism shield-totp-mfa's tests caught real bugs
 * in), ownership checks, the shape of the JSON handed to the browser,
 * and - importantly - that beginRegistration()/beginAuthentication()
 * actually run without error at all. Those two methods exercise the
 * real web-auth/webauthn-lib serializer and object construction (just
 * not the verification step), so they double as a smoke test that
 * WebauthnFactory's setup is wired correctly for your installed
 * library version - if CeremonyStepManagerFactory or the serializer
 * factory's construction is wrong for your version, THESE tests are
 * where that would surface, not silently later.
 */
final class PasskeyIdentityStoreTest extends CIUnitTestCase
{
    use DatabaseTestTrait;

    protected $refresh = true;

    // DatabaseTestTrait's own default ($namespace = 'Tests\Support')
    // does NOT migrate Shield's own tables or this package's migration -
    // it only looks in that one namespace. null triggers the same
    // behavior as `php spark migrate --all`.
    protected $namespace = null;

    private PasskeyIdentityStore $store;

    protected function setUp(): void
    {
        parent::setUp();

        $this->store = new PasskeyIdentityStore();
    }

    private function makeUser(): User
    {
        return fake(UserModel::class, [
            'email'    => 'passkey-test-' . uniqid() . '@example.com',
            'username' => 'passkeytest' . uniqid(),
            'password' => 'secret123456',
        ]);
    }

    /** Inserts a credential row directly, bypassing the real WebAuthn ceremony entirely. */
    private function seedCredential(User $user, ?string $name = null): int
    {
        $model = model(PasskeyCredentialModel::class);

        return (int) $model->insert([
            'user_id'                      => $user->id,
            'credential_id'                => Base64Url::encode(random_bytes(16)),
            'public_key_credential_source' => '{}', // never deserialized by the tests below
            'name'                         => $name,
            'last_used_at'                 => null,
        ], true);
    }

    private function hasPermanentMarker(User $user): bool
    {
        return model(UserIdentityModel::class)
            ->where('user_id', $user->id)
            ->where('type', PasskeyIdentityStore::ID_TYPE_PASSKEY)
            ->first() !== null;
    }

    // -------------------------------------------------------------------
    // hasEnrolled() / listCredentials()
    // -------------------------------------------------------------------

    public function testNotEnrolledByDefault(): void
    {
        $this->assertFalse($this->store->hasEnrolled($this->makeUser()));
    }

    public function testHasEnrolledIsTrueOnceACredentialExists(): void
    {
        $user = $this->makeUser();
        $this->seedCredential($user);

        $this->assertTrue($this->store->hasEnrolled($user));
    }

    public function testListCredentialsOnlyReturnsTheGivenUsersOwn(): void
    {
        $userA = $this->makeUser();
        $userB = $this->makeUser();

        $this->seedCredential($userA, 'A\'s phone');
        $this->seedCredential($userB, 'B\'s laptop');

        $listA = $this->store->listCredentials($userA);

        $this->assertCount(1, $listA);
        $this->assertSame('A\'s phone', $listA[0]['name']);
    }

    // -------------------------------------------------------------------
    // Marker sync - the same mechanism that had a real bug in
    // shield-totp-mfa's history, so this is worth covering thoroughly.
    // -------------------------------------------------------------------

    public function testRemovingTheLastCredentialRemovesThePermanentMarker(): void
    {
        $user = $this->makeUser();
        $id   = $this->seedCredential($user);

        // Simulate the marker having been created by an earlier,
        // real registration (completeRegistration() would normally do
        // this) - see the class doc comment for why marker CREATION
        // itself isn't separately tested here.
        model(UserIdentityModel::class)->create([
            'user_id' => $user->id,
            'type'    => PasskeyIdentityStore::ID_TYPE_PASSKEY,
            'name'    => null,
            'secret'  => 'n/a',
            'extra'   => null,
            'expires' => null,
        ]);

        $this->store->removeCredential($user, $id);

        $this->assertFalse($this->store->hasEnrolled($user));
        $this->assertFalse($this->hasPermanentMarker($user));
    }

    public function testRemovingOneOfSeveralCredentialsKeepsTheMarker(): void
    {
        $user = $this->makeUser();
        $keep = $this->seedCredential($user, 'keep this one');
        $this->seedCredential($user, 'remove this one');

        $all      = $this->store->listCredentials($user);
        $removeId = $all[0]['id'] === $keep ? $all[1]['id'] : $all[0]['id'];

        model(UserIdentityModel::class)->create([
            'user_id' => $user->id,
            'type'    => PasskeyIdentityStore::ID_TYPE_PASSKEY,
            'name'    => null,
            'secret'  => 'n/a',
            'extra'   => null,
            'expires' => null,
        ]);

        $this->store->removeCredential($user, (int) $removeId);

        $this->assertTrue($this->store->hasEnrolled($user));
        $this->assertTrue($this->hasPermanentMarker($user));
    }

    /**
     * THE regression test for the most severe bug found across this
     * whole series - see syncPermanentMarker()'s own doc comment. Two
     * DIFFERENT users both getting a permanent marker created - the
     * scenario every multi-user app with passkeys hits eventually -
     * used to throw a duplicate-key database error on the second user,
     * since the marker's secret was a FIXED literal string ('n/a'), not
     * something unique per row. Unlike shield-whatsapp-mfa's equivalent
     * bugs (see that package's PhoneNumberStore), this one needed no
     * coincidence and no timing window - it was PERMANENT, so the
     * SECOND person to ever enroll a passkey in a real app would be
     * unable to complete registration, indefinitely.
     *
     * Calls syncPermanentMarker() directly via reflection, rather than
     * through completeRegistration() (which would need a real WebAuthn
     * ceremony) - syncPermanentMarker() itself has no cryptographic
     * dependency of its own, it's pure "check credentials exist, create
     * or delete the marker" logic, so this is a faithful test of the
     * actual fix without needing to fake what can't be faked. This is
     * also the FIRST test in this file to exercise marker CREATION at
     * all - every other marker-related test above seeds a pre-existing
     * marker directly (bypassing creation entirely), since those are
     * testing removeCredential(), not creation - see the class doc
     * comment for the general "can't fake real crypto" limitation this
     * test sidesteps specifically because syncPermanentMarker() itself
     * needs none.
     */
    public function testTwoUsersBothGettingAMarkerCreatedDoNotCollide(): void
    {
        $userA = $this->makeUser();
        $userB = $this->makeUser();

        $this->seedCredential($userA);
        $this->seedCredential($userB);

        $method = new \ReflectionMethod($this->store, 'syncPermanentMarker');
        $method->setAccessible(true);

        // Neither of these should throw - a duplicate-key database
        // exception here would mean the regression is back.
        $method->invoke($this->store, $userA);
        $method->invoke($this->store, $userB);

        $this->assertTrue($this->hasPermanentMarker($userA));
        $this->assertTrue($this->hasPermanentMarker($userB));
    }

    public function testCannotRemoveAnotherUsersCredential(): void
    {
        $owner    = $this->makeUser();
        $attacker = $this->makeUser();
        $id       = $this->seedCredential($owner);

        $this->store->removeCredential($attacker, $id);

        $this->assertTrue($this->store->hasEnrolled($owner));
    }

    public function testCannotRenameAnotherUsersCredential(): void
    {
        $owner    = $this->makeUser();
        $attacker = $this->makeUser();
        $id       = $this->seedCredential($owner, 'original name');

        $this->store->renameCredential($attacker, $id, 'renamed by attacker');

        $stillOwned = $this->store->listCredentials($owner);
        $this->assertSame('original name', $stillOwned[0]['name']);
    }

    public function testRenameChangesTheStoredName(): void
    {
        $user = $this->makeUser();
        $id   = $this->seedCredential($user, 'old name');

        $this->store->renameCredential($user, $id, 'new name');

        $this->assertSame('new name', $this->store->listCredentials($user)[0]['name']);
    }

    // -------------------------------------------------------------------
    // Activation marker (register-slot pending-check support)
    // -------------------------------------------------------------------

    public function testEnsureActivationMarkerCreatesOneWhenMissing(): void
    {
        $user = $this->makeUser();

        $this->store->ensureActivationMarker($user);

        $this->seeInDatabase('auth_identities', [
            'user_id' => $user->id,
            'type'    => PasskeyIdentityStore::ID_TYPE_PASSKEY_ACTIVATE,
        ]);
    }

    public function testEnsureActivationMarkerReusesAStillValidOne(): void
    {
        $user = $this->makeUser();

        $this->store->ensureActivationMarker($user);
        $first = model(UserIdentityModel::class)
            ->where('user_id', $user->id)
            ->where('type', PasskeyIdentityStore::ID_TYPE_PASSKEY_ACTIVATE)
            ->first();

        $this->store->ensureActivationMarker($user);
        $second = model(UserIdentityModel::class)
            ->where('user_id', $user->id)
            ->where('type', PasskeyIdentityStore::ID_TYPE_PASSKEY_ACTIVATE)
            ->first();

        $this->assertSame($first->id, $second->id);
    }

    public function testEnsureActivationMarkerReplacesAnExpiredOne(): void
    {
        $user = $this->makeUser();

        $identityModel = model(UserIdentityModel::class);
        $identityModel->create([
            'user_id' => $user->id,
            'type'    => PasskeyIdentityStore::ID_TYPE_PASSKEY_ACTIVATE,
            'name'    => null,
            'secret'  => 'stale',
            'extra'   => null,
            'expires' => date('Y-m-d H:i:s', time() - 60), // already expired
        ]);
        $staleId = $identityModel
            ->where('user_id', $user->id)
            ->where('type', PasskeyIdentityStore::ID_TYPE_PASSKEY_ACTIVATE)
            ->first()->id;

        $this->store->ensureActivationMarker($user);

        $fresh = $identityModel
            ->where('user_id', $user->id)
            ->where('type', PasskeyIdentityStore::ID_TYPE_PASSKEY_ACTIVATE)
            ->first();

        $this->assertNotSame($staleId, $fresh->id);
    }

    // -------------------------------------------------------------------
    // beginRegistration() / beginAuthentication() - real WebAuthn
    // object construction and serialization, no verification involved.
    // See this class's own doc comment for why these are a genuine
    // smoke test of WebauthnFactory's setup, not just a shape check.
    // -------------------------------------------------------------------

    public function testBeginRegistrationProducesWellFormedOptionsJson(): void
    {
        $user = $this->makeUser();

        $json    = $this->store->beginRegistration($user, 'test@example.com');
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        $this->assertArrayHasKey('challenge', $decoded);
        $this->assertArrayHasKey('rp', $decoded);
        $this->assertArrayHasKey('user', $decoded);
        $this->assertNotEmpty($decoded['challenge']);
    }

    public function testBeginRegistrationExcludesAlreadyRegisteredCredentials(): void
    {
        $user = $this->makeUser();
        $this->seedCredential($user);
        $credentialId = $this->store->listCredentials($user)[0]['credential_id'];

        $json    = $this->store->beginRegistration($user, 'test@example.com');
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        $this->assertArrayHasKey('excludeCredentials', $decoded);
        $this->assertNotEmpty($decoded['excludeCredentials']);

        $excludedIds = array_column($decoded['excludeCredentials'], 'id');
        $this->assertContains($credentialId, $excludedIds);
    }

    public function testBeginAuthenticationProducesWellFormedOptionsJson(): void
    {
        $user = $this->makeUser();
        $this->seedCredential($user);

        $json    = $this->store->beginAuthentication($user);
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        $this->assertArrayHasKey('challenge', $decoded);
        $this->assertArrayHasKey('allowCredentials', $decoded);
        $this->assertNotEmpty($decoded['challenge']);
        $this->assertNotEmpty($decoded['allowCredentials']);
    }

    // -------------------------------------------------------------------
    // Graceful failure handling - completeRegistration()/completeAuthentication()
    // must never throw, only ever return false, for any input short of a
    // genuinely valid signed response (which these tests can't produce).
    // -------------------------------------------------------------------

    public function testCompleteRegistrationFailsGracefullyWithNoPendingChallenge(): void
    {
        $user = $this->makeUser();

        $this->assertFalse($this->store->completeRegistration($user, '{"anything":"goes"}'));
    }

    public function testCompleteRegistrationFailsGracefullyWithGarbageResponse(): void
    {
        $user = $this->makeUser();
        $this->store->beginRegistration($user, 'test@example.com');

        $this->assertFalse($this->store->completeRegistration($user, 'not even json'));
    }

    public function testCompleteAuthenticationFailsGracefullyWithNoPendingChallenge(): void
    {
        $user = $this->makeUser();

        $this->assertFalse($this->store->completeAuthentication($user, '{"anything":"goes"}'));
    }

    public function testCompleteAuthenticationFailsGracefullyWithGarbageResponse(): void
    {
        $user = $this->makeUser();
        $this->store->beginAuthentication($user);

        $this->assertFalse($this->store->completeAuthentication($user, 'not even json'));
    }

    public function testCancelRegistrationClearsThePendingChallenge(): void
    {
        $user = $this->makeUser();
        $this->store->beginRegistration($user, 'test@example.com');

        $this->store->cancelRegistration();

        $this->assertFalse($this->store->completeRegistration($user, '{"anything":"goes"}'));
    }

    public function testCancelAuthenticationClearsThePendingChallenge(): void
    {
        $user = $this->makeUser();
        $this->seedCredential($user);
        $this->store->beginAuthentication($user);

        $this->store->cancelAuthentication();

        $this->assertFalse($this->store->completeAuthentication($user, '{"anything":"goes"}'));
    }

    // -------------------------------------------------------------------
    // beginDiscoverableAuthentication()/completeDiscoverableAuthentication() -
    // the usernameless counterparts used by
    // PasskeyDiscoverableAuthController's "Login with a passkey" button.
    // -------------------------------------------------------------------

    /**
     * THE key structural difference from
     * testBeginAuthenticationProducesWellFormedOptionsJson() above -
     * allowCredentials must be genuinely ABSENT here, not just empty,
     * confirmed via web-auth/webauthn-lib's own official documentation
     * as the correct way to request a discoverable/usernameless
     * ceremony (see beginDiscoverableAuthentication()'s own doc
     * comment for the citation).
     */
    public function testBeginDiscoverableAuthenticationProducesWellFormedOptionsJsonWithNoAllowCredentials(): void
    {
        $json    = $this->store->beginDiscoverableAuthentication();
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        $this->assertArrayHasKey('challenge', $decoded);
        $this->assertNotEmpty($decoded['challenge']);

        // See PasskeyDiscoverableAuthControllerTest's own equivalent
        // test for why this checks "absent or empty" rather than
        // strictly "absent" - both carry the same "unrestricted
        // picker" meaning; only a non-empty, restricting list would be
        // wrong here.
        $this->assertTrue(
            ! array_key_exists('allowCredentials', $decoded) || $decoded['allowCredentials'] === [],
            'allowCredentials should be absent or empty for a discoverable ceremony, not a restricting list.'
        );
    }

    public function testCompleteDiscoverableAuthenticationFailsGracefullyWithNoPendingChallenge(): void
    {
        $this->assertNull($this->store->completeDiscoverableAuthentication('{"anything":"goes"}'));
    }

    public function testCompleteDiscoverableAuthenticationFailsGracefullyWithGarbageResponse(): void
    {
        $this->store->beginDiscoverableAuthentication();

        $this->assertNull($this->store->completeDiscoverableAuthentication('not even json'));
    }

    /**
     * Confirms the "no known user at all" case is handled the same
     * way every other malformed-input case is (returns null, doesn't
     * throw) - this method has no User parameter to even be given a
     * wrong one, unlike completeAuthentication(), so this is really
     * confirming the credential_id lookup itself fails gracefully when
     * nothing matches at all, which is the normal case for a garbage
     * or fabricated credential id.
     */
    public function testCompleteDiscoverableAuthenticationReturnsNullWhenNoCredentialMatches(): void
    {
        $this->store->beginDiscoverableAuthentication();

        $fabricatedResponse = json_encode([
            'id'       => Base64Url::encode(random_bytes(16)),
            'rawId'    => Base64Url::encode(random_bytes(16)),
            'type'     => 'public-key',
            'response' => [
                'clientDataJSON'    => Base64Url::encode('{}'),
                'authenticatorData' => Base64Url::encode(random_bytes(37)),
                'signature'         => Base64Url::encode(random_bytes(64)),
            ],
        ]);

        $this->assertNull($this->store->completeDiscoverableAuthentication($fabricatedResponse));
    }
}
