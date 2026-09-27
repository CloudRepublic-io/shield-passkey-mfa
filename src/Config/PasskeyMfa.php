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

    // -- Optional: passkey sign-in on the login page ----------------------

    /**
     * Off by default. When true, the login page's email field offers the
     * visitor's passkeys in the browser's own autofill dropdown
     * ("conditional UI"), next to any saved usernames. Choosing one signs
     * them in; anyone else types their email and password as normal.
     * Nothing ever pops up on its own.
     *
     * Needs the passkey-discoverable-auth-options / -verify routes from
     * routes-snippet.php and this package's passkey-login.js on your
     * login page - see "Optional: passkey sign-in on the login page" in
     * the README. Works only with discoverable passkeys (see
     * $residentKeyRequirement below).
     *
     * Replaces the earlier $enableEarlyAuthentication option (prompt when
     * the email field loses focus), which was removed: a prompt it had
     * already started could still appear after the visitor had clicked the
     * normal login button, even on the next page.
     */
    public bool $enablePasskeyAutofill = false;

    /**
     * Whether a successful passkey sign-in on the login page (autofill or
     * the "Login with a passkey" button) completes login OUTRIGHT, or
     * still requires whatever your app's own MFA would otherwise apply
     * (e.g. shield-mfa-dispatcher). Applies to both $enablePasskeyAutofill
     * (above) and $enableDiscoverableAuthentication (below).
     *
     * Defaults to true: a passkey is already a strong, phishing-resistant
     * credential that is inherently multi-factor (possession of the device
     * plus its own biometric/PIN unlock) and is verified directly by this
     * app. Set to false to layer your own MFA on top regardless.
     */
    public bool $earlyAuthenticationIsSufficient = true;

    // -- Optional: "Login with a passkey" button (no email needed) ----------

    /**
     * Off by default. When true, the login page can show a "Login with a
     * passkey" button: the visitor clicks it, the browser's own passkey
     * picker shows whichever passkeys it has for your site, and the
     * server identifies who they are from whichever one they choose. Uses
     * the same endpoints as $enablePasskeyAutofill above - turn on either
     * or both. Requires
     * "discoverable" (a.k.a. "resident key") credentials - see
     * $residentKeyRequirement below, and "Optional: 'Login with a
     * passkey' button (no email needed)" in the README for the full
     * picture, including what this means for ALREADY-registered
     * passkeys specifically.
     */
    public bool $enableDiscoverableAuthentication = false;

    /**
     * Controls what NEW registrations request from the authenticator -
     * 'discouraged', 'preferred', or 'required'. Only relevant if you
     * plan to use $enableDiscoverableAuthentication above (or might
     * later) - has no effect on anything else this package does.
     *
     * web-auth/webauthn-lib's own default, when nothing is specified
     * at all (which is what earlier versions of this package's own
     * beginRegistration() did), is equivalent to 'preferred' - meaning
     * already-registered passkeys MAY already be discoverable, with no
     * guarantee either way, since it depended entirely on what the
     * authenticator itself chose to do. 'required' guarantees future
     * registrations are discoverable, but will cause registration
     * itself to fail outright on any authenticator that cannot create
     * one at all - true passkey managers (Chrome/Edge/Safari's own
     * built-in ones) always can, but this is a real risk if this
     * package is ever used with older, non-passkey-aware security
     * keys. 'preferred' (the default here) asks for a discoverable
     * credential without hard-requiring one, matching the library's
     * own default behavior but stated explicitly rather than left
     * implicit.
     */
    public string $residentKeyRequirement = 'preferred';

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
