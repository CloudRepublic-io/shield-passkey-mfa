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
use PasskeyMfa\Controllers\PasskeyDiscoverableAuthController;
use PasskeyMfa\Libraries\Base64Url;
use PasskeyMfa\Models\PasskeyCredentialModel;

/**
 * Tests the discoverable-authentication controller by calling its
 * methods directly, via initController(), rather than through a full
 * HTTP round-trip - the same approach used throughout this series of
 * packages. As with PasskeyEarlyAuthControllerTest (this file's own
 * closest sibling), the actual cryptographic verification succeeding
 * isn't covered here - see PasskeyIdentityStoreTest's class doc
 * comment for why that's a deliberate, documented limitation across
 * this whole package.
 *
 * No actingAs() anywhere in this file - deliberately, for the same
 * reason as PasskeyEarlyAuthControllerTest: the visitor calling these
 * two endpoints isn't logged in, or even mid-login, at all. Unlike
 * that file, there's no email involved either - identity here comes
 * entirely from whichever credential the (simulated, since real crypto
 * can't be produced here) response claims to be.
 */
final class PasskeyDiscoverableAuthControllerTest extends CIUnitTestCase
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

        config('PasskeyMfa')->enableDiscoverableAuthentication = true;
    }

    private function makeUser(): User
    {
        return fake(UserModel::class, [
            'email'    => 'discoverabletest-' . uniqid() . '@example.com',
            'username' => 'discoverabletest' . uniqid(),
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

    private function makeController(array $post = []): PasskeyDiscoverableAuthController
    {
        $_POST = $post;

        /** @var IncomingRequest $request */
        $request = service('request', null, false);
        // CodeIgniter 4.7+ reads POST from a shared 'superglobals' snapshot
        // taken the first time anything touches the request, so the
        // $_POST assignment above is invisible to it - setGlobal() works
        // on 4.6 and 4.7 alike.
        $request->setGlobal('post', $post);

        $controller = new PasskeyDiscoverableAuthController();
        $controller->initController($request, service('response'), service('logger'));

        return $controller;
    }

    private function jsonBody(ResponseInterface $response): array
    {
        return json_decode($response->getBody(), true);
    }

    public function testOptionsReturns404WhenTheFeatureIsDisabled(): void
    {
        config('PasskeyMfa')->enableDiscoverableAuthentication = false;

        $response = $this->makeController()->options();

        $this->assertSame(404, $response->getStatusCode());
    }

    public function testVerifyReturns404WhenTheFeatureIsDisabled(): void
    {
        config('PasskeyMfa')->enableDiscoverableAuthentication = false;

        $response = $this->makeController(['credential' => 'anything'])->verify();

        $this->assertSame(404, $response->getStatusCode());
    }

    /**
     * Unlike PasskeyEarlyAuthControllerTest's equivalent, there is no
     * "available: false" case to test here at all - no email is given
     * up front for this endpoint to check enrollment against, so a
     * successful call always returns a challenge. Whether the visitor
     * actually has anything usable is left entirely to the browser's
     * own picker - see options()'s own doc comment for why.
     */
    public function testOptionsReturnsAChallengeWithNoAllowCredentials(): void
    {
        $response = $this->makeController()->options();
        $body     = $this->jsonBody($response);

        $this->assertArrayHasKey('options', $body);
        $this->assertArrayHasKey('challenge', $body['options']);

        // Confirmed via web-auth/webauthn-lib's own official docs: not
        // passing allowCredentials at all is the correct way to request
        // a discoverable/usernameless ceremony. Whether the library's
        // own serializer therefore omits the key entirely or includes
        // it as an empty array isn't asserted here - both achieve the
        // same functional goal (an unrestricted picker; MDN's own docs
        // confirm an empty array carries this same meaning), so this
        // checks only that it isn't a non-empty, restricting list.
        $this->assertTrue(
            ! array_key_exists('allowCredentials', $body['options']) || $body['options']['allowCredentials'] === [],
            'allowCredentials should be absent or empty for a discoverable ceremony, not a restricting list.'
        );
    }

    public function testVerifyFailsGracefullyWithNoPriorOptionsCall(): void
    {
        // No options() call first - nothing stashed in session for
        // verify() to check the response against.
        $response = $this->makeController(['credential' => 'anything'])->verify();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertFalse($this->jsonBody($response)['success']);
    }

    public function testVerifyFailsGracefullyWithAnEmptyCredential(): void
    {
        $this->makeController()->options();

        $response = $this->makeController(['credential' => ''])->verify();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertFalse($this->jsonBody($response)['success']);
    }

    public function testVerifyFailsGracefullyWithAGarbageCredential(): void
    {
        $this->makeController()->options();

        $response = $this->makeController(['credential' => 'not even json'])->verify();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertFalse($this->jsonBody($response)['success']);
    }

    /**
     * A credential ID that simply doesn't match anything on file -
     * this is the normal case for this endpoint (nothing narrows the
     * ceremony to one user ahead of time), so it's worth its own test
     * distinct from the generic "garbage" one above.
     */
    public function testVerifyFailsGracefullyWithANonMatchingCredential(): void
    {
        $this->makeController()->options();

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

        $response = $this->makeController(['credential' => $fabricatedResponse])->verify();

        $this->assertSame(401, $response->getStatusCode());
        $this->assertFalse($this->jsonBody($response)['success']);
    }

    public function testFailedVerificationDoesNotLogAnyoneIn(): void
    {
        $user = $this->makeUser();
        $this->seedCredential($user);

        $this->makeController()->options();
        $this->makeController(['credential' => ''])->verify();

        $this->assertNull(auth()->user());
    }
}
