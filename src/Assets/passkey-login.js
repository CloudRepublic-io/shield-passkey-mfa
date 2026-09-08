/**
 * Reference implementation of BOTH optional passkey-login shortcuts
 * this package supports, combined into a single file so a developer
 * only needs to include one script rather than two. This file is NOT
 * loaded automatically by this package anywhere - copy it into your
 * own login page's JavaScript (or adapt the logic inline), and adjust
 * the selectors/CSRF handling to match your actual login form's
 * markup.
 *
 * Each feature below is independent and optional - if your login page
 * only has the elements one of them needs, only that one activates;
 * the other's own setup silently does nothing. You do not need both
 * features enabled to use this file; a page with only an email field,
 * or only a "Login with a passkey" button, works exactly like it would
 * with only that feature's own standalone script.
 *
 * FEATURE 1 - "trigger a passkey prompt when the user tabs away from
 * the email field" (requires Config\PasskeyMfa::$enableEarlyAuthentication):
 * the pattern GitHub, Microsoft, and others use on their own login
 * pages. The visitor types their email, tabs to the password field (or
 * clicks elsewhere), and if that email has a registered passkey, the
 * browser's native prompt appears immediately - never typing a
 * password at all. See "FEATURE 1 DETAIL" further down for the full
 * step-by-step and this feature's own confirmed bug history.
 *
 * FEATURE 2 - a standalone "Login with a passkey" button (requires
 * Config\PasskeyMfa::$enableDiscoverableAuthentication): no email or
 * username needed at all. The visitor clicks the button, the browser's
 * own passkey picker shows whichever discoverable credentials it has
 * for this site across every account, and the server identifies who
 * logged in from whichever one gets chosen. See "FEATURE 2 DETAIL"
 * further down for the full step-by-step, including the discoverable-
 * credential prerequisite this one specifically depends on.
 *
 * WHY THESE TWO WERE COMBINED INTO ONE FILE - CONFIRMED, REAL BUG THIS
 * FIXES: when both features were shipped as separate files, a real
 * report showed them able to start two independent, competing WebAuthn
 * ceremonies at once - clicking the button while the email field still
 * had a value in it could cause the other feature's own blur-triggered
 * ceremony to also fire, if focus passed through the email field along
 * the way. Two overlapping navigator.credentials.get() calls produced
 * a confusing, inconsistent browser prompt on a second attempt, and
 * whichever response actually came back got checked against the WRONG
 * flow's own stored challenge server-side, producing a hard-to-
 * diagnose "Invalid challenge" error. The earlier, two-file version
 * fixed this with a shared global flag
 * (window.__passkeyMfaCeremonyInProgress) both scripts checked - this
 * consolidated version does the same coordination more directly, via
 * one local variable (`ceremonyInProgress` below) both features share
 * naturally, since they now live in the same scope. If you only enable
 * one of the two features, this coordination is inert and has no
 * effect either way.
 *
 * A LEFTOVER PROMPT CAN APPEAR ON THE NEXT PAGE - CONFIRMED, REAL BUG
 * FIXED HERE: a real report showed the browser's native passkey prompt
 * appearing on the 2FA challenge page - after a normal email+password
 * login had already been submitted and navigated away from the login
 * page entirely (most likely to happen when both fields arrive via
 * autofill and the visitor clicks "login" immediately, without ever
 * tabbing through the fields manually - the trigger for either feature
 * below). If the normal login form gets submitted WHILE either
 * feature's own options() fetch is still in flight, that feature's own
 * AbortController does not exist yet - aborting has nothing to call
 * .abort() on, so it silently does nothing - and the still-running
 * async function goes on to call navigator.credentials.get() AFTER the
 * browser has already begun navigating to the next page. Since the
 * browser's own native dialog is chrome-level UI, not part of the
 * page's own DOM, it can still render even once the new page has
 * loaded - appearing as a confusing, unexpected extra prompt there.
 * Fixed via a shared `formSubmitted` flag, checked independently of
 * whether either feature's own AbortController happens to exist yet at
 * every point a native prompt could otherwise be triggered - see that
 * variable's own declaration (shared state, top of this file) for the
 * full detail.
 *
 * A STUCK BROWSER CEREMONY CAN BLOCK EVERY PASSKEY OPERATION ON THE
 * DEVICE - CONFIRMED, REAL BROWSER BEHAVIOR BOTH FEATURES NOW WORK
 * AROUND: a real report showed that choosing a passkey identity in the
 * browser's own picker that ISN'T actually registered with this site -
 * something Feature 2's discoverable request can show, since it
 * displays every identity the platform has for its own ecosystem, not
 * just ones this app knows about - can leave navigator.credentials.get()
 * hanging for the platform's own full internal timeout (observed at
 * roughly 2 minutes) before it finally rejects. Worse: during that
 * entire window, the same report showed the BROWSER ITSELF (not just
 * this script) refusing to start any OTHER WebAuthn ceremony at all,
 * anywhere on the device - including a completely unrelated one, like
 * the normal password login's own separate 2FA challenge, or the OTHER
 * feature in this same file. This package has no way to prevent that
 * browser-level lock - it isn't something a website's own JavaScript
 * can control - but both features now impose their own 20-second
 * client-side timeout (via AbortController), so at least THIS page
 * gives up and re-enables itself with a clear message well before the
 * browser's own much longer timeout would, rather than leaving the UI
 * looking silently stuck for up to two minutes.
 *
 * CSRF TOKEN HANDLING - CONFIRMED, REAL BUG FIXED HERE, and the most
 * likely reason either feature can appear to do "nothing at all," even
 * for a visitor who DOES have a registered passkey: CodeIgniter's own
 * CSRF protection regenerates the token after every single request by
 * default (Config\Security::$regenerate). Each feature's own first
 * request (options()) is itself a POST, so by the time its response
 * comes back, the token has ALREADY changed - meaning a later verify()
 * call (and, separately, the page's own normal password-login form, if
 * the visitor falls back to typing their password) would submit with a
 * now-stale token and get rejected by CodeIgniter's own CSRF filter
 * before ever reaching a controller at all. A CSRF rejection returns
 * an HTML error page, not JSON - calling .json() on that throws, which
 * both features' own error handling swallows (Feature 1 silently,
 * Feature 2 by showing a generic status message), so this can fail
 * with no server-side log at all (the request never reached PHP code
 * that could log anything). Every relevant server response includes
 * the current token; this file updates one shared tracked copy after
 * every response from either feature, and writes it back into the
 * page's actual hidden CSRF field - so any later call from either
 * feature, and a fallback to the normal password form, always submit
 * with a valid, current token.
 *
 * ADJUST THESE TO MATCH YOUR ACTUAL LOGIN PAGE:
 *   - CSRF_FIELD_NAME (shared): must match Config\Security::$tokenName
 *     in your app (CodeIgniter's default is 'csrf_test_name').
 *   - EMAIL_FIELD_SELECTOR / PASSWORD_FIELD_SELECTOR (Feature 1 only).
 *   - BUTTON_SELECTOR / STATUS_SELECTOR (Feature 2 only).
 *   - The four route paths if you changed the route names in
 *     routes-snippet.php from the defaults.
 *
 * IF EITHER FEATURE SILENTLY DOES NOTHING (no browser prompt ever
 * appears, no error in the console either): CONFIRMED, REAL ISSUE
 * against a real app - check app/Config/Filters.php's $globals for a
 * login-required filter (e.g. 'session' or 'isLoggedIn'). If it's
 * applied globally, its own 'except' list needs to cover all four
 * routes below too, or the filter redirects them to your login page (a
 * 303) before either controller is ever reached - fetch() follows that
 * redirect silently and receives HTML back where JSON was expected.
 * Placing these routes under auth/a/... (routes-snippet.php's default)
 * already matches the exclusion pattern many Shield apps use for
 * Shield's own gateway-action routes - but check your own app's actual
 * exclusion list rather than assuming this is automatic.
 */
(function () {
    'use strict';

    // ---- Shared configuration ----
    var CSRF_FIELD_NAME = 'csrf_test_name';

    // ---- Shared state ----

    // The CSRF token's current value, as far as this file knows - null
    // until the first server response (from either feature) tells us
    // otherwise, in which case the page's own initial hidden field
    // value is used. See "CSRF TOKEN HANDLING" above.
    var currentCsrfValue = null;

    // True while EITHER feature has an active ceremony in flight - see
    // "WHY THESE TWO WERE COMBINED INTO ONE FILE" above for what this
    // prevents.
    var ceremonyInProgress = false;

    // CONFIRMED, REAL BUG FIXED HERE: a real report showed the
    // browser's native passkey prompt appearing on the 2FA challenge
    // page - AFTER a normal email+password login had already been
    // submitted and navigated away from this page entirely. Root
    // cause: if the normal login form is submitted (e.g. the visitor
    // clicks "login" immediately after their email and password arrive
    // via autofill, without ever tabbing through fields manually)
    // WHILE either feature's own options() fetch is still in flight,
    // that feature's own AbortController does not exist yet -
    // aborting has nothing to call .abort() on, so it silently does
    // nothing. The still-running async function then goes on to call
    // navigator.credentials.get() AFTER the browser has already begun
    // navigating to the next page - and since the browser's own
    // native dialog is chrome-level UI, not part of the page's own
    // DOM, it can still render even once the new page has loaded,
    // appearing as a confusing, unexpected extra prompt there. Shared
    // across both features (rather than local to just the email-blur
    // one) since either could, in principle, still be running when the
    // normal login form gets submitted - checked independently of
    // whether either feature's own AbortController happens to exist
    // yet, closing this gap regardless of timing.
    var formSubmitted = false;

    /**
     * Reads csrfHash from a server response (every endpoint from
     * either feature always includes it) and updates both this file's
     * own tracked value AND the page's actual hidden CSRF field, so a
     * subsequent call from either feature, or a fallback to the normal
     * password-login form, all submit with a current token rather than
     * the one the page happened to render with initially.
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

    // =========================================================================
    // FEATURE 1 DETAIL: trigger a passkey prompt on email-field blur
    // =========================================================================
    //
    // WHAT THIS DOES, end to end:
    //   1. User types their email, then tabs to the password field (or
    //      clicks elsewhere) - the blur event fires.
    //   2. This asks the server (passkey-early-auth-options) whether
    //      that email has a registered passkey. The response never
    //      reveals whether the email exists at all if it doesn't - see
    //      PasskeyEarlyAuthController's own doc comment.
    //   3. If a passkey is available, the browser's native passkey
    //      prompt appears (navigator.credentials.get()) - the user
    //      authenticates with their fingerprint/face/PIN/security key,
    //      never typing a password at all.
    //   4. The result is sent to the server (passkey-early-auth-verify)
    //      for verification; on success, the browser is redirected
    //      straight to wherever a normal login would have gone (or to
    //      the MFA challenge page, if
    //      Config\PasskeyMfa::$earlyAuthenticationIsSufficient is off).
    //   5. ANY failure at any step (no passkey available, the user
    //      cancels the browser's prompt, a network error, verification
    //      failure) falls through SILENTLY - the visitor simply
    //      continues with normal password login, exactly as if this
    //      feature weren't here at all. This must never block or
    //      visibly interrupt the form.
    //
    // CANCELLING - CONFIRMED, REAL FIX for prompts being hard to cancel
    // out of, or reappearing after cancelling: this actively aborts any
    // in-flight passkey ceremony (via navigator.credentials.get()'s own
    // "signal" option - the same AbortController-based mechanism MDN's
    // own docs and libraries like SimpleWebAuthn use for exactly this)
    // the moment the visitor types into the password field, or submits
    // the form - they are never required to manually dismiss the
    // browser's own dialog. Two distinct problems were involved, both
    // fixed here: (1) an earlier version's re-trigger guard (a plain
    // "in progress" flag) only prevented a SECOND ceremony while the
    // first was still running - it did nothing to stop the SAME email
    // value from triggering ANOTHER prompt on a later, separate blur
    // event (e.g. the visitor clicking back into the email field while
    // trying to dismiss the first prompt, then tabbing out again) - now
    // tracked per-value instead, so the identical email never
    // re-prompts twice; (2) starting a second
    // navigator.credentials.get() call while a first one is still
    // pending is a well-documented source of "operation already in
    // progress" errors and overlapping/duplicate browser dialogs in
    // some browsers - aborting the first ceremony before it would ever
    // be allowed to overlap with anything prevents this outright.
    //
    // SUSPECTED, NOT FULLY CONFIRMED - EDGE-SPECIFIC ABORT ISSUE: an
    // earlier version also aborted on the password field's own 'focus'
    // event (not just 'input'). A real report showed the ceremony
    // completing successfully in Edge specifically (the visitor sees
    // the browser's own success indication), but the later verify()
    // call never firing, with nothing visible in the console -
    // consistent with something aborting the in-flight
    // navigator.credentials.get() call between it succeeding and the
    // next line running, which would reject the promise with an
    // AbortError that the catch block below would otherwise swallow
    // silently. 'focus' was the more likely of the two listeners to
    // fire from browser-internal dialog/focus management rather than a
    // genuine, deliberate user action - 'input' requires the visitor to
    // actually type something, a much less ambiguous signal. Removed as
    // the most likely fix; the console.warn() below is also active by
    // default (not commented out) for exactly this reason - an earlier
    // version had it commented out, which is what made this failure
    // invisible to diagnose in the first place.
    //
    // ADJUST for your login form: EMAIL_FIELD_SELECTOR,
    // PASSWORD_FIELD_SELECTOR, and the two route paths below if changed
    // from routes-snippet.php's defaults.
    (function setupEarlyAuthentication() {
        var EMAIL_FIELD_SELECTOR    = 'input[name="email"]';
        var PASSWORD_FIELD_SELECTOR = 'input[name="password"]';
        var OPTIONS_URL             = '/auth/a/passkey-early/options';
        var VERIFY_URL              = '/auth/a/passkey-early/verify';

        var emailField    = document.querySelector(EMAIL_FIELD_SELECTOR);
        var passwordField = document.querySelector(PASSWORD_FIELD_SELECTOR);

        // Feature-detect WebAuthn support, and bail out entirely if the
        // login page doesn't have the field this feature expects -
        // never throw or interfere with the page if either is missing.
        if (!emailField || typeof window.PublicKeyCredential === 'undefined') {
            return;
        }

        // Tracks the email value a ceremony was last attempted for -
        // NOT just an "in progress" boolean, since the bug this fixes
        // was specifically about the SAME value re-prompting across
        // separate, later blur events, not just concurrent ones. A
        // different email value (e.g. the visitor corrected a typo) is
        // still always allowed to trigger a fresh attempt.
        var lastAttemptedEmail = null;

        // The AbortController for whichever ceremony is currently in
        // flight, if any - null whenever none is.
        var activeAbortController = null;

        emailField.addEventListener('blur', function () {
            var email = emailField.value.trim();

            if (email === '' || email === lastAttemptedEmail || ceremonyInProgress || formSubmitted) {
                return;
            }

            lastAttemptedEmail = email;
            attemptEarlyAuthentication(email);
        });

        // The moment the visitor actually types into the password
        // field, or submits the form some other way, any in-flight
        // ceremony is aborted immediately - see "CANCELLING" above for
        // why this is the actual fix, not just the re-trigger guard.
        if (passwordField) {
            passwordField.addEventListener('input', abortActiveCeremony);
        }

        if (emailField.form) {
            emailField.form.addEventListener('submit', function () {
                formSubmitted = true;
                abortActiveCeremony();
            });
        }

        function abortActiveCeremony() {
            if (activeAbortController) {
                activeAbortController.abort();
                activeAbortController = null;
            }
        }

        async function attemptEarlyAuthentication(email) {
            ceremonyInProgress = true;

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

                if (formSubmitted) {
                    // THE actual fix for the bug described above -
                    // checked here specifically because this is the
                    // last point before the browser's own native prompt
                    // would be triggered, and it does not depend on
                    // activeAbortController already existing the way
                    // abortActiveCeremony() does.
                    return;
                }

                // parseRequestOptionsFromJSON() is the WebAuthn Level 3
                // JSON helper - see this package's README ("Browser
                // support for the client-side JavaScript") for the
                // specific browser versions this requires.
                var publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(optionsData.options);

                // A fresh AbortController for THIS specific ceremony -
                // abortActiveCeremony() (above) can cancel it the
                // instant the visitor moves on, without them ever
                // needing to manually dismiss the browser's own dialog.
                activeAbortController = new AbortController();

                // CONFIRMED, REAL BROWSER BEHAVIOR THIS WORKS AROUND -
                // see the identical timeout in this file's Feature 2
                // section for the full explanation: a stuck
                // navigator.credentials.get() call (e.g. from an
                // unusual identity-selection scenario) can hang for the
                // platform's own full internal timeout (observed at
                // roughly 2 minutes), and during that window the
                // browser itself may refuse to start ANY other WebAuthn
                // ceremony at all, anywhere on the device. This timeout
                // means this feature gives up well before that. Tracked
                // separately from a genuine user cancellation
                // (timedOut, below) specifically so lastAttemptedEmail
                // is only cleared for THIS case - a real cancellation
                // should still leave it set, or the earlier fix for
                // "cancelling, then re-blurring the same untouched
                // email re-prompts again" would regress right back.
                var timedOut  = false;
                var timeoutId = setTimeout(function () {
                    timedOut = true;
                    abortActiveCeremony();
                }, 20000); // 20s

                // Opens the browser's native passkey prompt. Rejects if
                // the user cancels/dismisses it, if
                // abortActiveCeremony() fires (including via the
                // timeout above), or on various other WebAuthn errors -
                // caught below, always falling through silently either
                // way.
                var credential = await navigator.credentials.get({
                    publicKey: publicKey,
                    signal: activeAbortController.signal,
                });

                clearTimeout(timeoutId);
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
                // A failed verification also falls through silently -
                // the visitor still has their password to fall back
                // on, and updateCsrfToken() above already made sure
                // that fallback form still has a current, valid token
                // to submit with.
            } catch (error) {
                clearTimeout(timeoutId);
                activeAbortController = null;

                if (timedOut) {
                    // Our own timeout fired, not a deliberate user
                    // cancellation - clearing this allows a retry for
                    // the SAME email without the visitor needing to
                    // first change it, unlike a genuine cancellation
                    // (see the comment above timedOut's own
                    // declaration for why those two cases are handled
                    // differently).
                    lastAttemptedEmail = null;
                }

                // Includes the user cancelling the browser's own
                // passkey prompt (error.name === 'NotAllowedError',
                // typically), this script itself aborting the ceremony
                // via abortActiveCeremony() (error.name ===
                // 'AbortError', including via the timeout above), or
                // any other WebAuthn error. Deliberately does NOT block
                // or visibly interrupt the form either way - the
                // visitor always still has their password to fall back
                // on - but DOES log to the console, client-side only
                // (visible in the browser's own DevTools, not to the
                // visitor, and not sent anywhere) - see "SUSPECTED...
                // EDGE-SPECIFIC ABORT ISSUE" above for why this is
                // active by default rather than commented out.
                console.warn('Early passkey authentication skipped (' + (error && error.name ? error.name : 'unknown error') + '):', error);
            } finally {
                ceremonyInProgress = false;
            }
        }
    })();

    // =========================================================================
    // FEATURE 2 DETAIL: "Login with a passkey" button (no email needed)
    // =========================================================================
    //
    // HOW THIS DIFFERS FROM FEATURE 1: that one needs the visitor's
    // email BEFORE it can ask the server which credentials to offer
    // (allowCredentials). This one needs nothing at all up front - the
    // button click alone is the trigger, no allowCredentials is sent,
    // and the browser's own passkey picker shows whichever discoverable
    // credentials it has for this site, across every account. The
    // server figures out who logged in from whichever credential the
    // browser actually used - see PasskeyDiscoverableAuthController's
    // own doc comment for the security design behind that.
    //
    // WHAT THIS DOES, end to end:
    //   1. Visitor clicks the button.
    //   2. This asks the server (passkey-discoverable-auth-options) for
    //      a fresh challenge - no email or username involved at all.
    //   3. The browser's native passkey picker appears
    //      (navigator.credentials.get(), no allowCredentials) - the
    //      visitor picks whichever passkey they want to use for this
    //      site and authenticates with it.
    //   4. The result is sent to the server
    //      (passkey-discoverable-auth-verify) for verification; on
    //      success, the browser is redirected straight to wherever a
    //      normal login would have gone (or to the MFA challenge page,
    //      if Config\PasskeyMfa::$earlyAuthenticationIsSufficient is
    //      off - shared with Feature 1's own equivalent setting).
    //   5. ANY failure at any step (the visitor cancels the browser's
    //      own picker, no matching credential, a network error,
    //      verification failure) is shown via the status element below,
    //      and the button is re-enabled so they can try again or use
    //      their password instead - this never permanently blocks the
    //      login page.
    //
    // IF THE PICKER APPEARS BUT SHOWS NO PASSKEYS FOR THIS SITE, even
    // though the visitor has one registered: their credential may not
    // have been created as "discoverable" - see
    // Config\PasskeyMfa::$residentKeyRequirement's own doc comment. This
    // is a real, known limitation for credentials registered before
    // that setting existed, not a bug in this script.
    //
    // ADJUST for your login page: BUTTON_SELECTOR, STATUS_SELECTOR, and
    // the two route paths below if changed from routes-snippet.php's
    // defaults.
    (function setupDiscoverableAuthentication() {
        var BUTTON_SELECTOR = '#passkey-discoverable-login';
        var STATUS_SELECTOR = '#passkey-discoverable-status';
        var OPTIONS_URL      = '/auth/a/passkey-discoverable/options';
        var VERIFY_URL       = '/auth/a/passkey-discoverable/verify';

        var button = document.querySelector(BUTTON_SELECTOR);

        // Feature-detect WebAuthn support, and bail out entirely if the
        // login page doesn't have the button this feature expects -
        // never throw or interfere with the page if either is missing.
        if (!button || typeof window.PublicKeyCredential === 'undefined') {
            if (button) {
                button.style.display = 'none';
            }

            return;
        }

        var statusEl = document.querySelector(STATUS_SELECTOR);

        button.addEventListener('click', function () {
            if (ceremonyInProgress || formSubmitted) {
                return; // avoids a second overlapping navigator.credentials.get() call
            }

            attempt();
        });

        async function attempt() {
            ceremonyInProgress = true;
            button.disabled    = true;
            setStatus('');

            // CONFIRMED, REAL BROWSER BEHAVIOR THIS WORKS AROUND: a
            // real report showed that selecting a passkey identity NOT
            // actually registered with this site - visible in the
            // browser's own picker, since a discoverable request shows
            // every identity the platform has for its own ecosystem,
            // not just ones this app knows about - can leave
            // navigator.credentials.get() hanging for the PLATFORM's
            // own full internal timeout (observed at roughly 2
            // minutes) before it finally rejects. Worse, during that
            // entire window the same report showed the BROWSER ITSELF
            // (not just this script) refusing to start any OTHER
            // WebAuthn ceremony at all, anywhere on the device -
            // including a completely unrelated one, like the normal
            // password login's own separate 2FA challenge. This
            // package has no way to prevent that browser-level lock -
            // it isn't something a website's own JavaScript can
            // control - but this timeout at least means THIS button
            // gives up and re-enables itself well before the
            // browser's own timeout would, with a clear message,
            // rather than leaving the page looking silently stuck for
            // up to two minutes.
            var timeoutController = new AbortController();
            var timeoutId         = setTimeout(function () {
                timeoutController.abort();
            }, 20000); // 20s - generous for a genuine visitor picking a passkey, short enough not to feel broken

            try {
                var optionsResponse = await fetch(OPTIONS_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: csrfBodyParam(),
                    signal: timeoutController.signal,
                });

                if (!optionsResponse.ok) {
                    setStatus('This login option is not currently available.');

                    return; // e.g. 404 because the feature is disabled server-side
                }

                var optionsData = await optionsResponse.json();
                updateCsrfToken(optionsData);

                if (formSubmitted) {
                    // Shared with Feature 1's identical check - see
                    // formSubmitted's own declaration (shared state,
                    // top of file) for the full explanation. The normal
                    // login form was submitted while this was still
                    // waiting on options() - don't trigger the native
                    // prompt on what's about to be a different page.
                    return;
                }

                // parseRequestOptionsFromJSON() is the WebAuthn Level 3
                // JSON helper - see this package's README ("Browser
                // support for the client-side JavaScript") for the
                // specific browser versions this requires.
                var publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(optionsData.options);

                // No allowCredentials at all - the browser's own picker
                // shows whichever discoverable credentials it has for
                // this site's rpId, across every account.
                var credential = await navigator.credentials.get({
                    publicKey: publicKey,
                    signal: timeoutController.signal,
                });

                var verifyResponse = await fetch(VERIFY_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'credential=' + encodeURIComponent(JSON.stringify(credential.toJSON())) + '&' + csrfBodyParam(),
                    signal: timeoutController.signal,
                });

                var verifyData = await verifyResponse.json();
                updateCsrfToken(verifyData);

                if (verifyData.success) {
                    window.location.href = verifyData.redirect;

                    return;
                }

                setStatus('Could not sign you in with that passkey. Please try again, or use your password instead.');
            } catch (error) {
                if (error && error.name === 'AbortError') {
                    // This is OUR OWN timeout firing (see above), not
                    // the visitor cancelling anything - the browser's
                    // own ceremony was still hanging after 20 seconds.
                    setStatus('That took too long - please try again, or use your password instead.');
                } else if (error && error.name !== 'NotAllowedError') {
                    // NotAllowedError (visitor cancelling the browser's
                    // own picker, most commonly) is a normal, expected
                    // outcome, not treated as a genuine failure
                    // message.
                    setStatus('Something went wrong signing you in with a passkey. Please try again, or use your password instead.');
                }

                // Client-side only (visible in the browser's own
                // DevTools, not to the visitor, and not sent anywhere)
                // - uncomment during development if you need to see
                // exactly what went wrong:
                // console.warn('Discoverable passkey login skipped (' + (error && error.name ? error.name : 'unknown error') + '):', error);
            } finally {
                clearTimeout(timeoutId);
                ceremonyInProgress = false;
                button.disabled    = false;
            }
        }

        function setStatus(message) {
            if (statusEl) {
                statusEl.textContent = message;
            }
        }
    })();
})();
