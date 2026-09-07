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
 * CSRF TOKEN HANDLING - CONFIRMED, REAL BUG FIXED HERE, and the most
 * likely reason this whole feature can appear to do "nothing at all",
 * even for visitors who DO have a registered passkey: CodeIgniter's
 * own CSRF protection regenerates the token after every single request
 * by default (Config\Security::$regenerate). The options() call this
 * script makes on blur is ITSELF a POST request, so by the time its
 * response comes back, the token has ALREADY changed - meaning the
 * LATER verify() call (and, separately, the page's own normal
 * password-login form, if the visitor has no passkey and falls back to
 * typing their password) would submit with a now-stale token and get
 * rejected by CodeIgniter's own CSRF filter before ever reaching a
 * controller at all. A CSRF rejection returns an HTML error page, not
 * JSON - calling .json() on that throws, which step 5 above swallows
 * completely, so this failed completely silently: no server-side log
 * (the request never reached PHP code that could log anything), no
 * visible client-side error either. Both server responses
 * (PasskeyEarlyAuthController::options()/verify()) now include the
 * current token: this script updates its OWN copy after every
 * response, AND writes it back into the page's actual hidden CSRF
 * field - so both this script's own next call, and a fallback to the
 * normal password form, always submit with a valid, current token.
 *
 * CANCELLING - CONFIRMED, REAL FIX for prompts being hard to cancel out
 * of, or reappearing after cancelling: this script actively aborts any
 * in-flight passkey ceremony (via navigator.credentials.get()'s own
 * "signal" option - the same AbortController-based mechanism MDN's own
 * docs and libraries like SimpleWebAuthn use for exactly this) the
 * moment the visitor types into the password field, or submits the
 * form - they are never required to manually dismiss the browser's own
 * dialog. Two distinct problems were involved, both fixed here: (1) an
 * earlier version's re-trigger guard (a plain "in progress" flag) only
 * prevented a SECOND ceremony while the first was still running - it
 * did nothing to stop the SAME email value from triggering ANOTHER
 * prompt on a later, separate blur event (e.g. the visitor clicking
 * back into the email field while trying to dismiss the first prompt,
 * then tabbing out again) - now tracked per-value instead, so the
 * identical email never re-prompts twice; (2) starting a second
 * navigator.credentials.get() call while a first one is still pending
 * is a well-documented source of "operation already in progress"
 * errors and overlapping/duplicate browser dialogs in some browsers -
 * aborting the first ceremony before it would ever be allowed to
 * overlap with anything prevents this outright, rather than only
 * preventing it from occurring in the first place.
 *
 * SUSPECTED, NOT FULLY CONFIRMED - EDGE-SPECIFIC ABORT ISSUE: an
 * earlier version ALSO aborted on the password field's own 'focus'
 * event (not just 'input'). A real report showed the ceremony
 * completing successfully in Edge specifically (the visitor sees the
 * browser's own success indication), but the later verify() call never
 * firing, with nothing visible in the console. That earlier version
 * also had its own diagnostic console.debug() call commented out by
 * default, so any error being silently caught was never actually
 * visible either. 'focus' is now removed (only 'input' and the form's
 * own 'submit' event still abort an in-flight ceremony), on the theory
 * that Edge's own dialog/focus-management lifecycle briefly moved
 * focus to the password field at some point during or right after the
 * ceremony, and 'focus' was the more likely of the two listeners to
 * fire from browser-internal behavior rather than a genuine, deliberate
 * user action. console.warn() is also no longer commented out - client-
 * side only, never sent anywhere, so there's no downside to always
 * having it active, and it will show the real error name (e.g.
 * "AbortError") directly if this specific fix turns out to be
 * incomplete.
 *
 * ADJUST THESE FOUR THINGS to match your actual login page:
 *   - EMAIL_FIELD_SELECTOR: whatever selects your email/username input.
 *   - PASSWORD_FIELD_SELECTOR: whatever selects your password input -
 *     used only to know when to abort an in-flight ceremony.
 *   - CSRF_FIELD_NAME: must match Config\Security::$tokenName in your
 *     app (CodeIgniter's default is 'csrf_test_name') - this script
 *     reads the token's CURRENT value from the hidden field csrf_field()
 *     already rendered on your login form (updating it after every
 *     response - see "CSRF TOKEN HANDLING" above), so no separate
 *     token fetch is needed up front.
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

    var EMAIL_FIELD_SELECTOR    = 'input[name="email"]';
    var PASSWORD_FIELD_SELECTOR = 'input[name="password"]';
    var CSRF_FIELD_NAME         = 'csrf_test_name';
    var OPTIONS_URL             = '/auth/a/passkey-early/options';
    var VERIFY_URL              = '/auth/a/passkey-early/verify';

    var emailField    = document.querySelector(EMAIL_FIELD_SELECTOR);
    var passwordField = document.querySelector(PASSWORD_FIELD_SELECTOR);

    // Feature-detect WebAuthn support, and bail out entirely if the
    // login page doesn't have the field this script expects - never
    // throw or interfere with the page if either is missing.
    if (!emailField || typeof window.PublicKeyCredential === 'undefined') {
        return;
    }

    // Tracks the email value a ceremony was last attempted for - NOT
    // just an "in progress" boolean, since the bug this fixes was
    // specifically about the SAME value re-prompting across separate,
    // later blur events, not just concurrent ones. A different email
    // value (e.g. the visitor corrected a typo) is still always
    // allowed to trigger a fresh attempt.
    var lastAttemptedEmail = null;

    // The AbortController for whichever ceremony is currently in
    // flight, if any - null whenever none is.
    var activeAbortController = null;

    // The CSRF token's current value, as far as this script knows -
    // null until the first server response tells us otherwise, in
    // which case the page's own initial hidden field value is used.
    // See "CSRF TOKEN HANDLING" in this file's own header comment.
    var currentCsrfValue = null;

    emailField.addEventListener('blur', function () {
        var email = emailField.value.trim();

        if (email === '' || email === lastAttemptedEmail) {
            return;
        }

        lastAttemptedEmail = email;
        attemptEarlyAuthentication(email);
    });

    // The moment the visitor actually types into the password field,
    // or submits the form some other way, any in-flight ceremony is
    // aborted immediately - see this file's own header comment for
    // why this is the actual fix, not just the re-trigger guard above.
    //
    // SUSPECTED, NOT YET CONFIRMED, EDGE-SPECIFIC ISSUE: this used to
    // also abort on the password field's own 'focus' event. A real
    // report showed the ceremony completing successfully in Edge (the
    // visitor sees the browser's own success indication) but verify()
    // never being called afterward, with no error visible anywhere -
    // consistent with something aborting the in-flight
    // navigator.credentials.get() call between it succeeding and this
    // script's own next line running, which would reject the promise
    // with an AbortError that the catch block below swallows silently.
    // 'focus' was the more likely of the two listeners to fire from
    // browser-internal dialog/focus management, rather than a genuine,
    // deliberate user action - 'input' requires the visitor to actually
    // type something, a much less ambiguous signal. Removed here as
    // the most likely fix; if this turns out not to be the actual
    // cause, the uncommented console.error below (also new - the
    // previous version commented this out by default, which is
    // exactly what made this failure invisible in the first place)
    // will show the real error on the next report instead.
    if (passwordField) {
        passwordField.addEventListener('input', abortActiveCeremony);
    }

    if (emailField.form) {
        emailField.form.addEventListener('submit', abortActiveCeremony);
    }

    function abortActiveCeremony() {
        if (activeAbortController) {
            activeAbortController.abort();
            activeAbortController = null;
        }
    }

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
            updateCsrfToken(optionsData);

            if (!optionsData.available) {
                return; // no passkey for this email - let them type their password
            }

            // parseRequestOptionsFromJSON() is the WebAuthn Level 3 JSON
            // helper - see this package's README ("Browser support for
            // the client-side JavaScript") for the specific browser
            // versions this requires.
            var publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(optionsData.options);

            // A fresh AbortController for THIS specific ceremony -
            // abortActiveCeremony() (above) can cancel it the instant
            // the visitor moves on, without them ever needing to
            // manually dismiss the browser's own dialog.
            activeAbortController = new AbortController();

            // Opens the browser's native passkey prompt. Rejects if
            // the user cancels/dismisses it, if abortActiveCeremony()
            // fires, or on various other WebAuthn errors - caught
            // below, always falling through silently either way.
            var credential = await navigator.credentials.get({
                publicKey: publicKey,
                signal: activeAbortController.signal,
            });

            activeAbortController = null;

            var verifyResponse = await fetch(VERIFY_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'credential=' + encodeURIComponent(JSON.stringify(credential.toJSON())) + '&' + csrfBodyParam(),
            });

            var verifyData = await verifyResponse.json();
            updateCsrfToken(verifyData);

            if (verifyData.success) {
                window.location.href = verifyData.redirect;
            }
            // A failed verification also falls through silently - the
            // visitor still has their password to fall back on, and
            // updateCsrfToken() above already made sure that fallback
            // form still has a current, valid token to submit with.
        } catch (error) {
            activeAbortController = null;
            // Includes the user cancelling the browser's own passkey
            // prompt (error.name === 'NotAllowedError', typically), this
            // script itself aborting the ceremony via
            // abortActiveCeremony() (error.name === 'AbortError'), or
            // any other WebAuthn error. Deliberately does NOT block or
            // visibly interrupt the form either way - the visitor
            // always still has their password to fall back on - but
            // DOES log to the console now, rather than silently
            // swallowing everything: an earlier version commented this
            // line out by default, which is exactly what made a real,
            // confirmed bug (this file's own AbortController firing
            // unexpectedly in Edge - see the 'focus' listener removed
            // above) invisible to diagnose. This is client-side only
            // (visible in the browser's own DevTools, not to the
            // visitor, and not sent anywhere), so there's no downside
            // to leaving it active.
            console.warn('Early passkey authentication skipped (' + (error && error.name ? error.name : 'unknown error') + '):', error);
        }
    }

    /**
     * Reads csrfHash from a server response (both endpoints always
     * include it - see PasskeyEarlyAuthController's own doc comment for
     * why) and updates both this script's own tracked value AND the
     * page's actual hidden CSRF field, so a subsequent call from this
     * script, or a fallback to the normal password-login form, both
     * submit with a current token rather than the one the page
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
