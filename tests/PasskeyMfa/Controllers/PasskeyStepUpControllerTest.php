<?php

declare(strict_types=1);

namespace Tests\PasskeyMfa\Controllers;

use CodeIgniter\Config\Services;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Test\AuthenticationTesting;
use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;
use PasskeyMfa\Controllers\PasskeyStepUpController;
use PasskeyMfa\Libraries\Base64Url;
use PasskeyMfa\Models\PasskeyCredentialModel;

/**
 * Tests the step-up controller by calling its methods directly, via
 * initController(), rather than through a full HTTP round-trip - the
 * same approach used throughout this series of packages. Like
 * PasskeyMfaTest/PasskeyActivatorTest, the actual cryptographic
 * verification succeeding isn't covered here - see
 * PasskeyIdentityStoreTest's class doc comment for why that's a
 * deliberate, documented limitation across this whole package, not an
 * oversight specific to this file.
 *
 * Uses actingAs() (not a real Session::attempt()) - this controller is
 * for an already-fully-logged-in user, not someone mid-login, so
 * auth()->user() (what actingAs() sets up) is the correct state here,
 * not getPendingUser().
 */
final class PasskeyStepUpControllerTest extends CIUnitTestCase
{
    use DatabaseTestTrait;
    use AuthenticationTesting;

    protected $refresh = true;

    // DatabaseTestTrait's own default ($namespace = 'Tests\Support')
    // does NOT migrate Shield's own tables - it only looks in that one
    // namespace. null triggers the same behavior as
    // `php spark migrate --all`.
    protected $namespace = null;

    protected function setUp(): void
    {
        parent::setUp();

        // Defensive: this controller's own views use url_to(), which
        // needs a populated route collection - a call to resetServices()
        // anywhere earlier in the same PHPUnit process (this package's
        // own PasskeyActivatorTest calls it) wipes it. loadRoutes() is
        // safe to call even if routes are already loaded. See
        // shield-totp-mfa's RequireFreshTotpTest for the identical fix
        // applied for the identical reason.
        Services::routes()->loadRoutes();
    }

    private function makeUser(): User
    {
        return fake(UserModel::class, [
            'email'    => 'passkey-stepup-test-' . uniqid() . '@example.com',
            'username' => 'passkeystepuptest' . uniqid(),
            'password' => 'secret123456',
        ]);
    }

    private function seedCredential(User $user): void
    {
        model(PasskeyCredentialModel::class)->insert([
            'user_id'                      => $user->id,
            'credential_id'                => Base64Url::encode(random_bytes(16)),
            'public_key_credential_source' => '{}',
            'name'                         => 'Test credential',
            'last_used_at'                 => null,
        ]);
    }

    private function makeController(array $post = []): PasskeyStepUpController
    {
        $_POST = $post;

        /** @var IncomingRequest $request */
        $request = service('request', null, false);

        $controller = new PasskeyStepUpController();
        $controller->initController($request, service('response'), service('logger'));

        return $controller;
    }

    public function testShowRendersForAnEnrolledUser(): void
    {
        $user = $this->makeUser();
        $this->actingAs($user);
        $this->seedCredential($user);

        $body = $this->makeController()->show();

        $this->assertStringContainsString(lang('PasskeyMfa.verifyButton'), $body);
        $this->assertStringContainsString('passkey-options-json', $body);
    }

    public function testVerifyFailsGracefullyWithAnEmptyResponse(): void
    {
        $user = $this->makeUser();
        $this->actingAs($user);
        $this->seedCredential($user);

        $this->makeController()->show(); // starts the ceremony, stashing a challenge in session

        $response = $this->makeController(['credential' => ''])->verify();

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertNotEmpty(session('error'));
    }

    public function testVerifyFailsGracefullyWithAGarbageResponse(): void
    {
        $user = $this->makeUser();
        $this->actingAs($user);
        $this->seedCredential($user);

        $this->makeController()->show();

        $response = $this->makeController(['credential' => 'not even json'])->verify();

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertNotEmpty(session('error'));
    }

    public function testVerifyDoesNotStampTheStepUpSessionOnFailure(): void
    {
        $user = $this->makeUser();
        $this->actingAs($user);
        $this->seedCredential($user);

        $this->makeController()->show();
        $this->makeController(['credential' => ''])->verify();

        $this->assertNull(session(config('PasskeyMfa')->stepUpSessionKey));
    }
}
