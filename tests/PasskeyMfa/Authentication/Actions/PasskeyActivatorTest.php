<?php

declare(strict_types=1);

namespace Tests\PasskeyMfa\Authentication\Actions;

use CodeIgniter\Config\Services;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;
use PasskeyMfa\Authentication\Actions\PasskeyActivator;
use PasskeyMfa\Controllers\PasskeyActivatorController;
use PasskeyMfa\Libraries\PasskeyIdentityStore;
use ReflectionObject;

/**
 * Tests PasskeyActivator's show()/verify()/getType()/createIdentity()
 * and PasskeyActivatorController::skip() directly, rather than through
 * a full HTTP round-trip. See PasskeyMfaTest's class doc comment for
 * why the actual cryptographic success path isn't (and can't
 * meaningfully be) covered here.
 *
 * Uses a real Session::attempt() call with real credentials to put the
 * authenticator into a genuinely pending state - see PasskeyMfaTest's
 * class doc comment for why, and shield-totp-mfa's own test suite for
 * where this pattern was originally worked out.
 *
 * FULL FIX, mirroring shield-totp-mfa's TotpActivatorTest exactly
 * (see that class's own doc comment for the complete, diagnostic-backed
 * account - summarized here since this package hits the identical
 * issues):
 *
 *   - setUp() forces Config\Auth::$actions['register'] directly,
 *     rather than only documenting it as a prerequisite - a real gap
 *     that silently breaks if the test-running app's own
 *     app/Config/Auth.php doesn't happen to match.
 *   - resetServices() + session()->destroy() clear cached state left
 *     behind by whatever test ran immediately before this one in the
 *     same PHPUnit process.
 *   - Services::routes()->loadRoutes() undoes resetServices()'s own
 *     side effect of wiping the route collection.
 *   - simulateRegistrationStartup(), called by every test whose
 *     getPendingUser()-dependent method (show()/verify()/skip()) needs
 *     a genuinely pending user, sets the authenticator's own private
 *     $userState/$user properties directly via reflection - confirmed
 *     (via a real, multi-round diagnostic effort) that nothing short of
 *     this works once 'login' points at something other than this
 *     package's own action (e.g. shield-mfa-dispatcher's
 *     MfaDispatcher).
 */
final class PasskeyActivatorTest extends CIUnitTestCase
{
    use DatabaseTestTrait;

    protected $refresh = true;

    // DatabaseTestTrait's own default ($namespace = 'Tests\Support')
    // does NOT migrate Shield's own tables or this package's migration -
    // it only looks in that one namespace. null triggers the same
    // behavior as `php spark migrate --all`.
    protected $namespace = null;

    private const PASSWORD = 'secret123456';

    private $originalRegisterAction;

    protected function setUp(): void
    {
        parent::setUp();

        $this->resetServices();
        session()->destroy();
        Services::routes()->loadRoutes();

        $authConfig                      = config('Auth');
        $this->originalRegisterAction    = $authConfig->actions['register'] ?? null;
        $authConfig->actions['register'] = PasskeyActivator::class;
        // 'login' deliberately left untouched - see shield-totp-mfa's
        // TotpActivatorTest class doc comment for why forcing it to
        // null was tried there and caused a regression.
    }

    protected function tearDown(): void
    {
        config('Auth')->actions['register'] = $this->originalRegisterAction;

        parent::tearDown();
    }

    private function makeUser(): User
    {
        return fake(UserModel::class, [
            'email'    => 'passkey-activator-test-' . uniqid() . '@example.com',
            'username' => 'passkeyactivatortest' . uniqid(),
            'password' => self::PASSWORD,
            'active'   => false,
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

    /**
     * Sets the authenticator's own private $userState/$user properties
     * directly via reflection - confirmed, via shield-totp-mfa's own
     * multi-round diagnostic effort against its identical architecture,
     * to be the only way to correctly simulate a real registration
     * request's pending state once 'login' points at something other
     * than this package's own action (e.g. shield-mfa-dispatcher's
     * MfaDispatcher). See TotpActivatorTest's class doc comment (in
     * shield-totp-mfa) for the full, diagnostic-backed account of why
     * creating the database identity alone, and separately writing
     * session('user')['auth_action'] directly, were both tried and
     * confirmed NOT sufficient before this was found.
     *
     * 2 is the confirmed-working $userState value, observed directly
     * via a reflection dump of a genuinely working scenario, not
     * guessed or derived from documentation.
     */
    private function simulateRegistrationStartup(User $user): void
    {
        (new PasskeyActivator())->createIdentity($user);

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();
        $reflection    = new ReflectionObject($authenticator);

        $userStateProperty = $reflection->getProperty('userState');
        $userStateProperty->setAccessible(true);
        $userStateProperty->setValue($authenticator, 2);

        $userProperty = $reflection->getProperty('user');
        $userProperty->setAccessible(true);
        $userProperty->setValue($authenticator, $user);

        $field = setting('Auth.sessionConfig')['field'];
        $data  = session($field) ?? [];

        $data['id']                  = $user->id;
        $data['auth_action']         = PasskeyActivator::class;
        $data['auth_action_message'] = null;

        session()->set($field, $data);
    }

    public function testGetTypeReturnsTheActivationMarkerType(): void
    {
        $user = $this->makeUser();
        $this->attemptLogin($user);

        $this->assertSame(PasskeyIdentityStore::ID_TYPE_PASSKEY_ACTIVATE, (new PasskeyActivator())->getType());
    }

    public function testCreateIdentityEnsuresTheActivationMarkerExists(): void
    {
        $user = $this->makeUser();
        $this->attemptLogin($user);

        (new PasskeyActivator())->createIdentity($user);

        $this->seeInDatabase('auth_identities', [
            'user_id' => $user->id,
            'type'    => PasskeyIdentityStore::ID_TYPE_PASSKEY_ACTIVATE,
        ]);
    }

    public function testShowRendersForANewUser(): void
    {
        $user = $this->makeUser();
        $this->attemptLogin($user);
        $this->simulateRegistrationStartup($user);

        $body = (new PasskeyActivator())->show();

        $this->assertStringContainsString(lang('PasskeyMfa.registerButton'), $body);
        $this->assertStringContainsString('passkey-options-json', $body);
    }

    public function testVerifyFailsGracefullyWithAnEmptyResponse(): void
    {
        $user = $this->makeUser();
        $this->attemptLogin($user);
        $this->simulateRegistrationStartup($user);

        (new PasskeyActivator())->show();

        (new PasskeyActivator())->verify($this->requestWithPost(['credential' => '']));

        $this->assertNotEmpty(session('error'));

        $fresh = model(UserModel::class)->find($user->id);
        $this->assertFalse((bool) $fresh->active);
    }

    public function testSkipActivatesUserWithoutRegisteringAPasskey(): void
    {
        $user = $this->makeUser();
        $this->attemptLogin($user);
        $this->simulateRegistrationStartup($user);

        $store    = new PasskeyIdentityStore();
        $response = (new PasskeyActivatorController())->skip();

        $this->assertSame(302, $response->getStatusCode());
        $this->assertFalse($store->hasEnrolled($user));

        $fresh = model(UserModel::class)->find($user->id);
        $this->assertTrue((bool) $fresh->active);
    }

    // NOT covered here: verify()'s $wasAlreadyActive branch (see the
    // class doc comment - it's what makes this class safe to reuse for
    // shield-mfa-dispatcher's forced-setup flow). That branch only
    // runs after completeRegistration() succeeds, which needs a
    // genuinely valid signed WebAuthn response - the exact same
    // limitation documented at length in PasskeyIdentityStoreTest's
    // class doc comment applies here too. The identical logic pattern
    // IS directly tested in shield-totp-mfa's TotpActivatorTest
    // (testVerifyForAnAlreadyActiveUserRedirectsToLoginNotRegistration),
    // since TOTP's success path just needs a matching 6-digit code,
    // not real cryptography.
}
