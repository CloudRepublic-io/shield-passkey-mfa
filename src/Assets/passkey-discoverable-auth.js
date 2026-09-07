/**
 * Example implementation of a "Login with a passkey" button - the
 * discoverable/usernameless counterpart to passkey-early-auth.js. This
 * file is NOT loaded automatically by this package anywhere - copy it
 * into your own login page's JavaScript (or adapt the logic inline),
 * and adjust the selectors/CSRF handling to match your actual login
 * form's markup.
 *
 * Requires Config\PasskeyMfa::$enableDiscoverableAuthentication to be
 * true - both endpoints this script calls return 404 otherwise.
 *
 * HOW THIS DIFFERS FROM passkey-early-auth.js: that script needs the
 * visitor's email BEFORE it can ask the server which credentials to
 * offer (allowCredentials). This one needs nothing at all up front -
 * the button click alone is the trigger, no allowCredentials is sent,
 * and the browser's own passkey picker shows whichever discoverable
 * credentials it has for this site, across every account. The server
 * figures out who logged in from whichever credential the browser
 * actually used - see PasskeyDiscoverableAuthController's own doc
 * comment for the security design behind that.
 *
 * WHAT THIS DOES, end to end:
 *   1. Visitor clicks the button.
 *   2. This script asks the server (passkey-discoverable-auth-options)
 *      for a fresh challenge - no email or username involved at all.
 *   3. The browser's native passkey picker appears
 *      (navigator.credentials.get(), no allowCredentials) - the
 *      visitor picks whichever passkey they want to use for this site
 *      and authenticates with it.
 *   4. The result is sent to the server
 *      (passkey-discoverable-auth-verify) for verification; on
 *      success, the browser is redirected straight to wherever a
 *      normal login would have gone (or to the MFA challenge page, if
 *      Config\PasskeyMfa::$earlyAuthenticationIsSufficient is off -
 *      shared with passkey-early-auth.js's own equivalent setting).
 *   5. ANY failure at any step (the visitor cancels the browser's own
 *      picker, no matching credential, a network error, verification
 *      failure) is shown via the status element below, and the button
 *      is re-enabled so they can try again or use their password
 *      instead - this never permanently blocks the login page.
 *
 * CSRF TOKEN HANDLING: identical mechanism to passkey-early-auth.js -
 * see that file's own header comment ("CSRF TOKEN HANDLING") for the
 * full, confirmed explanation of why this matters. Both server
 * responses here include the current token; this script updates its
 * own copy and the page's actual hidden CSRF field after every
 * response.
 *
 * ADJUST THESE THREE THINGS to match your actual login page:
 *   - BUTTON_SELECTOR: whatever selects your "Login with a passkey"
 *     button.
 *   - CSRF_FIELD_NAME: must match Config\Security::$tokenName in your
 *     app (CodeIgniter's default is 'csrf_test_name').
 *   - The two route paths (OPTIONS_URL/VERIFY_URL) if you changed the
 *     route names in routes-snippet.php from the defaults.
 *
 * IF THE BUTTON DOES NOTHING (no browser prompt ever appears, and no
 * error shown): check app/Config/Filters.php's $globals for a
 * login-required filter - the same confirmed, real issue documented in
 * passkey-early-auth.js's own header comment applies here identically.
 * Placing these routes under auth/a/... (routes-snippet.php's default)
 * already matches the exclusion pattern many Shield apps use.
 *
 * IF THE PICKER APPEARS BUT SHOWS NO PASSKEYS FOR THIS SITE, even
 * though the visitor has one registered: their credential may not have
 * been created as "discoverable" - see
 * Config\PasskeyMfa::$residentKeyRequirement's own doc comment. This is
 * a real, known limitation for credentials registered before that
 * setting existed, not a bug in this script.
 */
(function () {
    'use strict';

    var BUTTON_SELECTOR = '#passkey-discoverable-login';
    var STATUS_SELECTOR = '#passkey-discoverable-status';
    var CSRF_FIELD_NAME  = 'csrf_test_name';
    var OPTIONS_URL      = '/auth/a/passkey-discoverable/options';
    var VERIFY_URL       = '/auth/a/passkey-discoverable/verify';

    var button = document.querySelector(BUTTON_SELECTOR);

    // Feature-detect WebAuthn support, and bail out entirely if the
    // login page doesn't have the button this script expects - never
    // throw or interfere with the page if either is missing.
    if (!button || typeof window.PublicKeyCredential === 'undefined') {
        if (button) {
            button.style.display = 'none';
        }

        return;
    }

    var statusEl          = document.querySelector(STATUS_SELECTOR);
    var currentCsrfValue   = null;
    var attemptInProgress  = false;

    button.addEventListener('click', function () {
        if (attemptInProgress) {
            return; // avoids a second overlapping navigator.credentials.get() call
        }

        attempt();
    });

    async function attempt() {
        attemptInProgress = true;
        button.disabled   = true;
        setStatus('');

        try {
            var optionsResponse = await fetch(OPTIONS_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: csrfBodyParam(),
            });

            if (!optionsResponse.ok) {
                setStatus('This login option is not currently available.');

                return; // e.g. 404 because the feature is disabled server-side
            }

            var optionsData = await optionsResponse.json();
            updateCsrfToken(optionsData);

            // parseRequestOptionsFromJSON() is the WebAuthn Level 3 JSON
            // helper - see this package's README ("Browser support for
            // the client-side JavaScript") for the specific browser
            // versions this requires.
            var publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(optionsData.options);

            // No allowCredentials at all - the browser's own picker
            // shows whichever discoverable credentials it has for this
            // site's rpId, across every account.
            var credential = await navigator.credentials.get({ publicKey: publicKey });

            var verifyResponse = await fetch(VERIFY_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'credential=' + encodeURIComponent(JSON.stringify(credential.toJSON())) + '&' + csrfBodyParam(),
            });

            var verifyData = await verifyResponse.json();
            updateCsrfToken(verifyData);

            if (verifyData.success) {
                window.location.href = verifyData.redirect;

                return;
            }

            setStatus('Could not sign you in with that passkey. Please try again, or use your password instead.');
        } catch (error) {
            // Includes the visitor cancelling the browser's own picker
            // (error.name === 'NotAllowedError', typically) - a normal,
            // expected outcome, not treated as a genuine failure message.
            if (error && error.name !== 'NotAllowedError' && error.name !== 'AbortError') {
                setStatus('Something went wrong signing you in with a passkey. Please try again, or use your password instead.');
            }

            // Client-side only (visible in the browser's own DevTools,
            // not to the visitor, and not sent anywhere) - uncomment
            // during development if you need to see exactly what went
            // wrong:
            // console.warn('Discoverable passkey login skipped (' + (error && error.name ? error.name : 'unknown error') + '):', error);
        } finally {
            attemptInProgress = false;
            button.disabled   = false;
        }
    }

    function setStatus(message) {
        if (statusEl) {
            statusEl.textContent = message;
        }
    }

    /**
     * Reads csrfHash from a server response (both endpoints always
     * include it - see PasskeyDiscoverableAuthController's own doc
     * comment) and updates both this script's own tracked value AND
     * the page's actual hidden CSRF field, so a subsequent call from
     * this script, or a fallback to the normal password-login form,
     * both submit with a current token rather than the one the page
     * happened to render with initially.
     */
    function updateCsrfToken(data) {
        if (!data || typeof data.csrfHash !== 'string') {
            return;
        }

        currentCsrfValue = data.csrfHash;

        var tokenField = document.querySelector('input[name="' + CSRF_FIELD_NAME + '"]');
        if (tokenField) {
            tokenField.value = data.csrfHash;
        }
    }

    function csrfBodyParam() {
        if (currentCsrfValue !== null) {
            return CSRF_FIELD_NAME + '=' + encodeURIComponent(currentCsrfValue);
        }

        var tokenField = document.querySelector('input[name="' + CSRF_FIELD_NAME + '"]');

        return tokenField ? CSRF_FIELD_NAME + '=' + encodeURIComponent(tokenField.value) : '';
    }
})();
