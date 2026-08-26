<?php

declare(strict_types=1);

namespace Tests\PasskeyMfa\Filters;

use CodeIgniter\Config\Services;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Test\AuthenticationTesting;
use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;
use PasskeyMfa\Filters\RequireFreshPasskey;
use PasskeyMfa\Libraries\Base64Url;
use PasskeyMfa\Models\PasskeyCredentialModel;

/**
 * Tests RequireFreshPasskey::before() directly, rather than through a
 * full HTTP round-trip to a real protected route - mirrors
 * shield-totp-mfa's own RequireFreshTotpTest exactly. See that file's
 * doc comment for why this approach doesn't need your app to have a
 * dedicated test-only protected route wired up.
 */
final class RequireFreshPasskeyTest extends CIUnitTestCase
{
    use DatabaseTestTrait;
    use AuthenticationTesting;

    protected $refresh = true;

    // DatabaseTestTrait's own default ($namespace = 'Tests\Support')
    // does NOT migrate Shield's own tables or this package's migration -
    // it only looks in that one namespace. null triggers the same
    // behavior as `php spark migrate --all`.
    protected $namespace = null;

    /**
     * Saved/restored around the one test that mutates a shared config
     * property - see tearDown().
     */
    private ?bool $originalStepUpRequiresEnrollment = null;

    protected function setUp(): void
    {
        parent::setUp();

        // Makes this file self-contained rather than dependent on
        // PasskeyMfaTest/PasskeyActivatorTest happening to run first in
        // the same PHPUnit process: this filter's redirect()->route()
        // calls need a populated route collection, and a call to
        // resetServices() anywhere earlier in the same process (this
        // package's own tests call it - see PasskeyActivatorTest's own
        // setUp() for why) wipes it. loadRoutes() is safe to call even
        // if routes are already loaded. See shield-totp-mfa's
        // RequireFreshTotpTest for the identical fix applied for the
        // identical reason.
        Services::routes()->loadRoutes();
    }

    protected function tearDown(): void
    {
        if ($this->originalStepUpRequiresEnrollment !== null) {
            config('PasskeyMfa')->stepUpRequiresEnrollment = $this->originalStepUpRequiresEnrollment;
            $this->originalStepUpRequiresEnrollment         = null;
        }

        parent::tearDown();
    }

    private function makeUser(string $prefix): User
    {
        return fake(UserModel::class, [
            'email'    => $prefix . '-' . uniqid() . '@example.com',
            'username' => $prefix . uniqid(),
            'password' => 'secret123456',
        ]);
    }

    /**
     * Seeds a credential row directly, bypassing the real WebAuthn
     * ceremony entirely - the filter only cares whether the user has
     * any credential at all (hasEnrolled()), so this is safe for
     * testing the filter's own logic without needing real crypto - see
     * PasskeyIdentityStoreTest's class doc comment for the fuller
     * explanation of why this is the established pattern in this
     * package's own test suite.
     */
    private function enroll(User $user): void
    {
        model(PasskeyCredentialModel::class)->insert([
            'user_id'                      => $user->id,
            'credential_id'                => Base64Url::encode(random_bytes(16)),
            'public_key_credential_source' => '{}',
            'name'                         => 'Test credential',
            'last_used_at'                 => null,
        ]);
    }

    public function testUnauthenticatedRequestIsIgnored(): void
    {
        $filter = new RequireFreshPasskey();

        $result = $filter->before(service('request'));

        // Not this filter's job - it defers to whatever login-required
        // filter runs alongside it.
        $this->assertNull($result);
    }

    public function testEnrolledUserWithoutRecentStepUpIsRedirectedToChallenge(): void
    {
        $user = $this->makeUser('stepup-test');
        $this->actingAs($user);
        $this->enroll($user);

        $result = (new RequireFreshPasskey())->before(service('request'));

        $this->assertNotNull($result);
    }

    public function testFreshStepUpSessionLetsTheRequestThrough(): void
    {
        $user = $this->makeUser('stepup-test');
        $this->actingAs($user);
        $this->enroll($user);

        session()->set(config('PasskeyMfa')->stepUpSessionKey, time());

        $result = (new RequireFreshPasskey())->before(service('request'));

        $this->assertNull($result);
    }

    public function testExpiredStepUpSessionIsRedirectedAgain(): void
    {
        $user = $this->makeUser('stepup-test');
        $this->actingAs($user);
        $this->enroll($user);

        $config = config('PasskeyMfa');
        session()->set($config->stepUpSessionKey, time() - $config->stepUpFreshnessSeconds - 60);

        $result = (new RequireFreshPasskey())->before(service('request'));

        $this->assertNotNull($result);
    }

    public function testUnenrolledUserPassesThroughByDefault(): void
    {
        $user = $this->makeUser('stepup-unenrolled');

        $this->actingAs($user);

        $result = (new RequireFreshPasskey())->before(service('request'));

        // Default policy: nothing to challenge them with, so let them
        // through rather than lock them out entirely - see
        // $config->stepUpRequiresEnrollment to change this.
        $this->assertNull($result);
    }

    public function testUnenrolledUserIsRedirectedToEnrollWhenRequired(): void
    {
        $user = $this->makeUser('stepup-forced');

        $this->actingAs($user);

        // Saved so tearDown() can restore it - config objects are
        // cached/shared by CodeIgniter's Factories, so mutating one
        // directly without restoring it would leak into every other
        // test that runs afterward in the same PHPUnit process,
        // regardless of which test class they're in.
        $config                                 = config('PasskeyMfa');
        $this->originalStepUpRequiresEnrollment = $config->stepUpRequiresEnrollment;
        $config->stepUpRequiresEnrollment        = true;

        $result = (new RequireFreshPasskey())->before(service('request'));

        $this->assertNotNull($result);
    }
}
