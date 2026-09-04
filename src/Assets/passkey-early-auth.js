/**
 * Example implementation of "trigger a passkey prompt when the user
 * tabs away from the email field" - the pattern GitHub, Microsoft, and
 * others use on their own login pages. This file is NOT loaded
 * automatically by this package anywhere - copy it into your own
 * login page's JavaScript (or adapt the logic inline), and adjust the
 * selectors/CSRF handling to match your actual login form's markup.
 *
 * Requires Config\PasskeyMfa::$enableEarlyAuthentication to be true -
 * both endpoints this script calls return 404 otherwise.
 *
 * WHAT THIS DOES, end to end:
 *   1. User types their email, then tabs to the password field (or
 *      clicks elsewhere) - the blur event fires.
 *   2. This script asks the server (passkey-early-auth-options)
 *      whether that email has a registered passkey. The response never
 *      reveals whether the email exists at all if it doesn't - see
 *      PasskeyEarlyAuthController's own doc comment.
 *   3. If a passkey is available, the browser's native passkey prompt
 *      appears (navigator.credentials.get()) - the user authenticates
 *      with their fingerprint/face/PIN/security key, never typing a
 *      password at all.
 *   4. The result is sent to the server (passkey-early-auth-verify)
 *      for verification; on success, the browser is redirected
 *      straight to wherever a normal login would have gone (or to the
 *      MFA challenge page, if Config\PasskeyMfa::$earlyAuthenticationIsSufficient
 *      is off).
 *   5. ANY failure at any step (no passkey available, the user
 *      cancels the browser's prompt, a network error, verification
 *      failure) falls through SILENTLY - the visitor simply continues
 *      with normal password login, exactly as if this script weren't
 *      here at all. This must never block or visibly interrupt the
 *      form.
 *
 * ADJUST THESE THREE THINGS to match your actual login page:
 *   - EMAIL_FIELD_SELECTOR: whatever selects your email/username input.
 *   - CSRF_FIELD_NAME: must match Config\Security::$tokenName in your
 *     app (CodeIgniter's default is 'csrf_test_name') - this script
 *     reads the token's CURRENT value from the hidden field csrf_field()
 *     already rendered on your login form, so no separate token
 *     fetch is needed.
 *   - The two route paths (OPTIONS_URL/VERIFY_URL) if you changed the
 *     route names in routes-snippet.php from the defaults.
 *
 * IF THIS SILENTLY DOES NOTHING (no browser prompt ever appears, and
 * no error in the console either): CONFIRMED, REAL ISSUE against a
 * real app - check app/Config/Filters.php's $globals for a
 * login-required filter (e.g. 'session' or 'isLoggedIn'). If it's
 * applied globally, its own 'except' list needs to cover these two
 * routes too, or the filter redirects them to your login page (a 303)
 * before this controller is ever reached - fetch() follows that
 * redirect silently and receives HTML back where JSON was expected,
 * which the deliberately-silent catch block below swallows completely.
 * Placing these routes under auth/a/... (routes-snippet.php's
 * default) already matches the exclusion pattern many Shield apps use
 * for Shield's own gateway-action routes - but check your own
 * app's actual exclusion list rather than assuming this is automatic.
 */
(function () {
    'use strict';

    var EMAIL_FIELD_SELECTOR = 'input[name="email"]';
    var CSRF_FIELD_NAME      = 'csrf_test_name';
    var OPTIONS_URL          = '/auth/a/passkey-early/options';
    var VERIFY_URL           = '/auth/a/passkey-early/verify';

    var emailField = document.querySelector(EMAIL_FIELD_SELECTOR);

    // Feature-detect WebAuthn support, and bail out entirely if the
    // login page doesn't have the field this script expects - never
    // throw or interfere with the page if either is missing.
    if (!emailField || typeof window.PublicKeyCredential === 'undefined') {
        return;
    }

    var inProgress = false;

    emailField.addEventListener('blur', function () {
        var email = emailField.value.trim();

        if (email === '' || inProgress) {
            return;
        }

        inProgress = true;
        attemptEarlyAuthentication(email).finally(function () {
            inProgress = false;
        });
    });

    async function attemptEarlyAuthentication(email) {
        try {
            var optionsResponse = await fetch(OPTIONS_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'email=' + encodeURIComponent(email) + '&' + csrfBodyParam(),
            });

            if (!optionsResponse.ok) {
                return; // e.g. 404 because the feature is disabled server-side
            }

            var optionsData = await optionsResponse.json();

            if (!optionsData.available) {
                return; // no passkey for this email - let them type their password
            }

            // parseRequestOptionsFromJSON() is the WebAuthn Level 3 JSON
            // helper - see this package's README ("Browser support for
            // the client-side JavaScript") for the specific browser
            // versions this requires.
            var publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(optionsData.options);

            // Opens the browser's native passkey prompt. Throws if the
            // user cancels/dismisses it, or on various other WebAuthn
            // errors - caught below, always falling through silently.
            var credential = await navigator.credentials.get({ publicKey: publicKey });

            var verifyResponse = await fetch(VERIFY_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'credential=' + encodeURIComponent(JSON.stringify(credential.toJSON())) + '&' + csrfBodyParam(),
            });

            var verifyData = await verifyResponse.json();

            if (verifyData.success) {
                window.location.href = verifyData.redirect;
            }
            // A failed verification also falls through silently - the
            // visitor still has their password to fall back on.
        } catch (error) {
            // Includes the user cancelling the browser's own passkey
            // prompt (a normal, expected outcome, not a real error) -
            // deliberately silent either way. If you want visibility
            // into genuine failures during development, uncomment:
            // console.debug('Early passkey authentication skipped:', error);
        }
    }

    function csrfBodyParam() {
        var tokenField = document.querySelector('input[name="' + CSRF_FIELD_NAME + '"]');

        return tokenField ? CSRF_FIELD_NAME + '=' + encodeURIComponent(tokenField.value) : '';
    }
})();
