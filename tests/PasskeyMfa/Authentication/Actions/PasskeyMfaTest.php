<?php

declare(strict_types=1);

namespace Tests\PasskeyMfa\Authentication\Actions;

use CodeIgniter\Config\Services;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;
use PasskeyMfa\Authentication\Actions\PasskeyMfa;
use PasskeyMfa\Libraries\Base64Url;
use PasskeyMfa\Libraries\PasskeyIdentityStore;
use PasskeyMfa\Models\PasskeyCredentialModel;

/**
 * Tests PasskeyMfa's show()/verify()/getType()/createIdentity()
 * directly, rather than through a full HTTP round-trip - and, for the
 * real cryptographic success path, not at all. See this package's
 * README and PasskeyIdentityStoreTest's class doc comment for why:
 * that needs a real browser and authenticator to produce a genuinely
 * valid signed response.
 *
 * What IS covered here:
 *   - getType()/createIdentity() behave correctly for an already-
 *     enrolled user (the only state Shield should ever route a login
 *     attempt to this action for at all).
 *   - show() actually renders for an enrolled user - this exercises
 *     beginAuthentication(), which runs real web-auth/webauthn-lib
 *     object construction/serialization, so it doubles as a smoke test
 *     of WebauthnFactory's setup for your installed library version.
 *   - verify() fails gracefully (not with an exception) for a garbage
 *     or empty response.
 *
 * Uses a real Session::attempt() call with real credentials to put the
 * authenticator into a genuinely pending state, rather than actingAs()
 * (fully logged in - a different state from what getPendingUser()
 * checks for) - the same approach worked out, through a lot of trial
 * and error, in the shield-totp-mfa package's own test suite.
 *
 * setUp() forces Config\Auth::$actions['login'] to PasskeyMfa::class
 * directly, and clears cached state left behind by whatever test ran
 * immediately before this one in the same PHPUnit process - both
 * confirmed necessary via the shield-totp-mfa package's own extensive
 * diagnostic work (its README and TotpMfaTest/TotpActivatorTest class
 * doc comments have the full account; summarized here since this
 * package hits the identical issues, not repeated in full):
 *
 *   - DatabaseTestTrait's own $refresh resets the DATABASE between
 *     test methods but does nothing to the SESSION or to CI4's own
 *     cached SERVICE instances (confirmed: a second attempt() in the
 *     same process, without clearing both, throws Shield's own
 *     "already logged in or in pending login state" LogicException).
 *   - resetServices() (which clears the cached, shared authenticator
 *     instance - the actual missing piece, not session()->destroy()
 *     alone) also wipes the route collection as a side effect
 *     (confirmed via CodeIgniter's own docs) - Services::routes()->loadRoutes()
 *     is required afterward or every url_to()/route_to() call in this
 *     package's own views throws "The route for ... cannot be found".
 *   - Only documenting "assumes PasskeyMfa is registered as 'login'"
 *     in a comment, rather than forcing it, silently breaks if the
 *     test-running app's own app/Config/Auth.php points 'login'
 *     somewhere else (e.g. shield-mfa-dispatcher's MfaDispatcher).
 */
final class PasskeyMfaTest extends CIUnitTestCase
{
    use DatabaseTestTrait;

    protected $refresh = true;

    // DatabaseTestTrait's own default ($namespace = 'Tests\Support')
    // does NOT migrate Shield's own tables or this package's migration -
    // it only looks in that one namespace. null triggers the same
    // behavior as `php spark migrate --all`.
    protected $namespace = null;

    private const PASSWORD = 'secret123456';

    private $originalLoginAction;

    protected function setUp(): void
    {
        parent::setUp();

        $this->resetServices();
        session()->destroy();
        Services::routes()->loadRoutes();

        $authConfig                   = config('Auth');
        $this->originalLoginAction    = $authConfig->actions['login'] ?? null;
        $authConfig->actions['login'] = PasskeyMfa::class;
    }

    protected function tearDown(): void
    {
        config('Auth')->actions['login'] = $this->originalLoginAction;

        parent::tearDown();
    }

    private function makeUser(): User
    {
        return fake(UserModel::class, [
            'email'    => 'passkey-login-test-' . uniqid() . '@example.com',
            'username' => 'passkeylogintest' . uniqid(),
            'password' => self::PASSWORD,
        ]);
    }

    /**
     * Seeds a credential row and the permanent marker directly,
     * bypassing the real WebAuthn ceremony entirely - equivalent to
     * what a successful completeRegistration() would have left behind.
     */
    private function enrollFakeCredential(User $user): void
    {
        model(PasskeyCredentialModel::class)->insert([
            'user_id'                      => $user->id,
            'credential_id'                => Base64Url::encode(random_bytes(16)),
            'public_key_credential_source' => '{}',
            'name'                         => 'Test credential',
            'last_used_at'                 => null,
        ]);

        model(UserIdentityModel::class)->create([
            'user_id' => $user->id,
            'type'    => PasskeyIdentityStore::ID_TYPE_PASSKEY,
            'name'    => null,
            'secret'  => 'n/a',
            'extra'   => null,
            'expires' => null,
        ]);
    }

    private function requestWithPost(array $post): IncomingRequest
    {
        $_POST = $post;

        /** @var IncomingRequest $request */
        $request = service('request', null, false);

        return $request;
    }

    private function attemptLogin(User $user): void
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();
        $result        = $authenticator->attempt([
            'email'    => $user->email,
            'password' => self::PASSWORD,
        ]);

        $this->assertTrue($result->isOK(), 'attempt() did not succeed with the test user\'s real credentials.');
    }

    public function testGetTypeReturnsThePermanentMarkerType(): void
    {
        $user = $this->makeUser();
        $this->enrollFakeCredential($user);
        $this->attemptLogin($user);

        $this->assertSame(PasskeyIdentityStore::ID_TYPE_PASSKEY, (new PasskeyMfa())->getType());
    }

    public function testCreateIdentityIsAGenuineNoOp(): void
    {
        $user = $this->makeUser();
        $this->enrollFakeCredential($user);
        $this->attemptLogin($user);

        $this->assertSame('', (new PasskeyMfa())->createIdentity($user));
    }

    public function testShowRendersForAnEnrolledUser(): void
    {
        $user = $this->makeUser();
        $this->enrollFakeCredential($user);
        $this->attemptLogin($user);

        $body = (new PasskeyMfa())->show();

        $this->assertStringContainsString(lang('PasskeyMfa.verifyButton'), $body);
        $this->assertStringContainsString('passkey-options-json', $body);
    }

    public function testVerifyFailsGracefullyWithAnEmptyResponse(): void
    {
        $user = $this->makeUser();
        $this->enrollFakeCredential($user);
        $this->attemptLogin($user);

        (new PasskeyMfa())->show(); // starts the ceremony, stashing a challenge in session

        (new PasskeyMfa())->verify($this->requestWithPost(['credential' => '']));

        $this->assertNotEmpty(session('error'));
    }

    public function testVerifyFailsGracefullyWithAGarbageResponse(): void
    {
        $user = $this->makeUser();
        $this->enrollFakeCredential($user);
        $this->attemptLogin($user);

        (new PasskeyMfa())->show();

        (new PasskeyMfa())->verify($this->requestWithPost(['credential' => 'not even json']));

        $this->assertNotEmpty(session('error'));
    }
}
