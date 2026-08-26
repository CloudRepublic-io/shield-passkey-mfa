<?php

declare(strict_types=1);

namespace Tests\PasskeyMfa\Controllers;

use CodeIgniter\Config\Services;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Test\AuthenticationTesting;
use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;
use PasskeyMfa\Controllers\PasskeySettingsController;
use PasskeyMfa\Libraries\Base64Url;
use PasskeyMfa\Libraries\PasskeyIdentityStore;
use PasskeyMfa\Models\PasskeyCredentialModel;

/**
 * Tests the settings controller's index()/rename()/delete() by calling
 * them directly, via initController(), rather than through a full HTTP
 * round-trip - the same approach used throughout this series of
 * packages. enroll()/confirm() aren't covered here - they need a real
 * WebAuthn ceremony, which PasskeyIdentityStoreTest's class doc
 * comment explains isn't meaningfully fakeable.
 *
 * Uses actingAs() (not a real Session::attempt()) - this controller is
 * for an already-fully-logged-in user managing their own settings, not
 * someone mid-login, so auth()->user() (what actingAs() sets up) is
 * the correct state here, not getPendingUser().
 */
final class PasskeySettingsControllerTest extends CIUnitTestCase
{
    use DatabaseTestTrait;
    use AuthenticationTesting;

    protected $refresh = true;

    // DatabaseTestTrait's own default ($namespace = 'Tests\Support')
    // does NOT migrate Shield's own tables or this package's migration -
    // it only looks in that one namespace. null triggers the same
    // behavior as `php spark migrate --all`.
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
            'email'    => 'passkey-settings-test-' . uniqid() . '@example.com',
            'username' => 'passkeysettingstest' . uniqid(),
            'password' => 'secret123456',
        ]);
    }

    private function seedCredential(User $user, ?string $name = null): int
    {
        return (int) model(PasskeyCredentialModel::class)->insert([
            'user_id'                      => $user->id,
            'credential_id'                => Base64Url::encode(random_bytes(16)),
            'public_key_credential_source' => '{}',
            'name'                         => $name,
            'last_used_at'                 => null,
        ], true);
    }

    private function makeController(array $post = []): PasskeySettingsController
    {
        $_POST = $post;

        /** @var IncomingRequest $request */
        $request = service('request', null, false);

        $controller = new PasskeySettingsController();
        $controller->initController($request, service('response'), service('logger'));

        return $controller;
    }

    public function testIndexRendersTheCredentialList(): void
    {
        $user = $this->makeUser();
        $this->actingAs($user);
        $this->seedCredential($user, 'My phone');

        $body = $this->makeController()->index();

        $this->assertStringContainsString('My phone', $body);
    }

    public function testIndexRendersWithNoCredentialsToo(): void
    {
        $user = $this->makeUser();
        $this->actingAs($user);

        $body = $this->makeController()->index();

        $this->assertStringContainsString(lang('PasskeyMfa.noCredentials'), $body);
    }

    public function testRenameChangesTheStoredName(): void
    {
        $user = $this->makeUser();
        $this->actingAs($user);
        $id = $this->seedCredential($user, 'old name');

        $this->makeController(['name' => 'new name'])->rename($id);

        $store = new PasskeyIdentityStore();
        $this->assertSame('new name', $store->listCredentials($user)[0]['name']);
    }

    public function testRenameRejectsAnEmptyName(): void
    {
        $user = $this->makeUser();
        $this->actingAs($user);
        $id = $this->seedCredential($user, 'old name');

        $this->makeController(['name' => ''])->rename($id);

        $store = new PasskeyIdentityStore();
        $this->assertSame('old name', $store->listCredentials($user)[0]['name']);
    }

    public function testDeleteRemovesTheCredential(): void
    {
        $user = $this->makeUser();
        $this->actingAs($user);
        $id = $this->seedCredential($user);

        $this->makeController()->delete($id);

        $store = new PasskeyIdentityStore();
        $this->assertFalse($store->hasEnrolled($user));
    }

    public function testCannotDeleteAnotherUsersCredentialThroughTheController(): void
    {
        $owner    = $this->makeUser();
        $attacker = $this->makeUser();
        $id       = $this->seedCredential($owner);

        $this->actingAs($attacker);
        $this->makeController()->delete($id);

        $store = new PasskeyIdentityStore();
        $this->assertTrue($store->hasEnrolled($owner));
    }
}
