<?php

declare(strict_types=1);

namespace Tests\PasskeyMfa\Controllers;

use CodeIgniter\Config\Services;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;
use PasskeyMfa\Controllers\PasskeyEarlyAuthController;
use PasskeyMfa\Libraries\Base64Url;
use PasskeyMfa\Models\PasskeyCredentialModel;

/**
 * Tests the early-authentication controller by calling its methods
 * directly, via initController(), rather than through a full HTTP
 * round-trip - the same approach used throughout this series of
 * packages. As with PasskeyMfaTest/PasskeyActivatorTest/PasskeyStepUpControllerTest,
 * the actual cryptographic verification succeeding isn't covered here
 * - see PasskeyIdentityStoreTest's class doc comment for why that's a
 * deliberate, documented limitation across this whole package.
 *
 * No actingAs() anywhere in this file - deliberately. Unlike every
 * other controller in this package, the visitor calling these two
 * endpoints isn't logged in, or even mid-login, at all; they're
 * identified purely by whatever email they typed into the login form.
 */
final class PasskeyEarlyAuthControllerTest extends CIUnitTestCase
{
    use DatabaseTestTrait;

    protected $refresh = true;

    // DatabaseTestTrait's own default ($namespace = 'Tests\Support')
    // does NOT migrate Shield's own tables - it only looks in that one
    // namespace. null triggers the same behavior as
    // `php spark migrate --all`.
    protected $namespace = null;

    protected function setUp(): void
    {
        parent::setUp();

        // Defensive - see PasskeyStepUpControllerTest's own setUp()
        // for why this is needed regardless of test execution order.
        Services::routes()->loadRoutes();

        config('PasskeyMfa')->enableEarlyAuthentication = true;
    }

    private function makeUser(string $email): User
    {
        return fake(UserModel::class, [
            'email'    => $email,
            'username' => 'earlyauthtest' . uniqid(),
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

    private function makeController(array $post = []): PasskeyEarlyAuthController
    {
        $_POST = $post;

        /** @var IncomingRequest $request */
        $request = service('request', null, false);

        $controller = new PasskeyEarlyAuthController();
        $controller->initController($request, service('response'), service('logger'));

        return $controller;
    }

    private function jsonBody(ResponseInterface $response): array
    {
        return json_decode($response->getBody(), true);
    }

    public function testOptionsReturns404WhenTheFeatureIsDisabled(): void
    {
        config('PasskeyMfa')->enableEarlyAuthentication = false;

        $response = $this->makeController(['email' => 'anyone@example.com'])->options();

        $this->assertSame(404, $response->getStatusCode());
    }

    public function testVerifyReturns404WhenTheFeatureIsDisabled(): void
    {
        config('PasskeyMfa')->enableEarlyAuthentication = false;

        $response = $this->makeController(['credential' => 'anything'])->verify();

        $this->assertSame(404, $response->getStatusCode());
    }

    public function testOptionsReportsUnavailableForANonExistentEmail(): void
    {
        $response = $this->makeController(['email' => 'nobody-' . uniqid() . '@example.com'])->options();

        $this->assertSame(['available' => false], $this->jsonBody($response));
    }

    public function testOptionsReportsUnavailableForAnEmptyEmail(): void
    {
        $response = $this->makeController(['email' => ''])->options();

        $this->assertSame(['available' => false], $this->jsonBody($response));
    }

    /**
     * THE email-enumeration-safety test. A real, existing user with no
     * registered passkey must produce the EXACT SAME response shape as
     * a non-existent email (tested above) - otherwise this endpoint
     * could be used to probe which email addresses have accounts at
     * all, regardless of passkey status.
     */
    public function testOptionsReportsUnavailableIdenticallyForAnExistingUserWithNoPasskey(): void
    {
        $user = $this->makeUser('no-passkey-' . uniqid() . '@example.com');

        $response = $this->makeController(['email' => $user->email])->options();

        $this->assertSame(['available' => false], $this->jsonBody($response));
    }

    public function testOptionsReturnsAChallengeForAUserWithARegisteredPasskey(): void
    {
        $user = $this->makeUser('has-passkey-' . uniqid() . '@example.com');
        $this->seedCredential($user);

        $response = $this->makeController(['email' => $user->email])->options();
        $body     = $this->jsonBody($response);

        $this->assertTrue($body['available']);
        $this->assertArrayHasKey('options', $body);
        $this->assertArrayHasKey('challenge', $body['options']);
    }

    public function testVerifyFailsGracefullyWithNoPriorOptionsCall(): void
    {
        // No options() call first - nothing stashed in session for
        // verify() to re-derive a user from.
        $response = $this->makeController(['credential' => 'anything'])->verify();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertFalse($this->jsonBody($response)['success']);
    }

    public function testVerifyFailsGracefullyWithAnEmptyCredential(): void
    {
        $user = $this->makeUser('verify-empty-' . uniqid() . '@example.com');
        $this->seedCredential($user);

        $this->makeController(['email' => $user->email])->options(); // stashes the pending email in session

        $response = $this->makeController(['credential' => ''])->verify();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertFalse($this->jsonBody($response)['success']);
    }

    public function testVerifyFailsGracefullyWithAGarbageCredential(): void
    {
        $user = $this->makeUser('verify-garbage-' . uniqid() . '@example.com');
        $this->seedCredential($user);

        $this->makeController(['email' => $user->email])->options();

        $response = $this->makeController(['credential' => 'not even json'])->verify();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertFalse($this->jsonBody($response)['success']);
    }

    public function testFailedVerificationDoesNotLogAnyoneIn(): void
    {
        $user = $this->makeUser('verify-nologin-' . uniqid() . '@example.com');
        $this->seedCredential($user);

        $this->makeController(['email' => $user->email])->options();
        $this->makeController(['credential' => ''])->verify();

        $this->assertNull(auth()->user());
    }
}
