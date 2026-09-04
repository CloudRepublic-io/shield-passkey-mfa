<?php

declare(strict_types=1);

namespace Config;

use CodeIgniter\Config\BaseConfig;

/**
 * Copy this file to app/Config/PasskeyMfa.php in the host application.
 *
 * Covers the core passkey flow (registration, login verification,
 * credential management) plus step-up auth for sensitive pages
 * (RequireFreshPasskey filter) - added after this package was first
 * built, following the exact pattern shield-totp-mfa's own
 * RequireFreshTotp filter established. Doesn't re-implement "remember
 * this device" - that one's still specific to shield-totp-mfa/
 * shield-whatsapp-mfa's own login flows.
 */
class PasskeyMfa extends BaseConfig
{
    /**
     * Shown to the user's authenticator/password manager during
     * registration (e.g. "Sign in to My App").
     */
    public string $rpName = 'My App';

    /**
     * The Relying Party ID - must be your app's actual domain (or a
     * registrable parent of it, e.g. 'example.com' covers
     * 'app.example.com' too), with NO scheme and NO port. A mismatch
     * here is the single most common reason a passkey ceremony fails
     * outright - the browser enforces this strictly, it isn't just a
     * label.
     */
    public string $rpId = 'example.com';

    /**
     * How long a generated registration/login challenge stays valid,
     * in seconds, before the ceremony must be restarted.
     */
    public int $challengeTtl = 300; // 5 minutes

    // -- Step-up auth for sensitive pages (RequireFreshPasskey filter) ------

    /**
     * How long, in seconds, a step-up passkey challenge stays "fresh"
     * before a protected page requires the user to authenticate again.
     * See shield-totp-mfa's Config\TotpMfa::$stepUpFreshnessSeconds for
     * the full explanation of why this is independent of anything
     * login-time.
     */
    public int $stepUpFreshnessSeconds = 900; // 15 minutes

    /** Session key used to record when the user last passed a step-up challenge. */
    public string $stepUpSessionKey = 'passkey_step_up_verified_at';

    /**
     * If true, a user with no registered passkey at all is redirected
     * to enroll before a step-up-protected page is reached, rather
     * than being let through with nothing to challenge them against.
     */
    public bool $stepUpRequiresEnrollment = false;

    /**
     * Route name to send an unenrolled user to when
     * $stepUpRequiresEnrollment is true. Defaults to the standalone
     * PasskeySettingsController's enrollment route.
     */
    public string $stepUpEnrollRouteName = 'passkey-settings-enroll';

    // -- Optional: trigger a passkey prompt from the login form -------------

    /**
     * Off by default - a genuinely different UX/security shape from
     * this package's main job (a SECOND factor after a password), so
     * it's opt-in even once PasskeyEarlyAuthController's routes are
     * added, not automatic.
     *
     * When true, exposes two endpoints a developer can call from their
     * OWN login page's JavaScript - typically wired to fire on blur of
     * the email field, so a returning user with a registered passkey
     * gets the browser's native passkey prompt immediately, before
     * ever touching the password field (the same pattern GitHub,
     * Microsoft, and others use). See "Optional: trigger a passkey
     * prompt from the login form" in the README for the full setup,
     * including the example JavaScript this package ships but does
     * NOT auto-inject anywhere - you choose whether and how to wire it
     * into your own login page's markup.
     */
    public bool $enableEarlyAuthentication = false;

    /**
     * Whether a successful early passkey authentication (see above)
     * completes the login OUTRIGHT, or still requires whatever your
     * app's own MFA would otherwise apply (e.g.
     * shield-mfa-dispatcher).
     *
     * Defaults to true - unlike shield-oauth-login's equivalent toggle
     * ($triggerMfaAfterSso, which defaults to STILL requiring MFA),
     * this one defaults the other way: a passkey is already a strong,
     * phishing-resistant credential that's inherently multi-factor
     * (possession of the device + its own biometric/PIN unlock) and
     * verified DIRECTLY by this app, not delegated to a third-party
     * IdP whose own security posture this app has no way to verify.
     * Treating it as sufficient on its own is a more defensible
     * default here. Still your call - set to false to layer your own
     * MFA on top regardless.
     */
    public bool $earlyAuthenticationIsSufficient = true;

    /**
     * View paths used by this package, keyed by a logical name - the
     * same pattern Shield itself uses for Config\Auth::$views, and
     * every other package in this series uses for its own views.
     * Override any of these in your own copy of this file. Whatever
     * you substitute in must accept the same variables the default
     * expects, AND include the same client-side WebAuthn JavaScript -
     * check the corresponding file under src/Views/ carefully, this
     * isn't just markup.
     */
    public array $views = [
        'passkey_activator_enroll' => 'PasskeyMfa\Views\passkey_activator_enroll',
        'passkey_mfa_verify'       => 'PasskeyMfa\Views\passkey_mfa_verify',
        'passkey_settings_index'   => 'PasskeyMfa\Views\passkey_settings_index',
        'passkey_settings_enroll'  => 'PasskeyMfa\Views\passkey_settings_enroll',
        'passkey_step_up'          => 'PasskeyMfa\Views\passkey_step_up',
    ];

    public function __construct()
    {
        parent::__construct();

        $this->rpName = env('passkeyMfa.rpName', $this->rpName);
        $this->rpId   = env('passkeyMfa.rpId', $this->rpId);
    }
}
