/**
 * passkey-login.js - reference implementation of the two optional passkey
 * shortcuts this package supports on your LOGIN page. It is NOT loaded
 * automatically anywhere: copy it into your login page (or adapt it
 * inline) and adjust the settings at the top of the code to match your
 * login form's markup and routes.
 *
 * FEATURE 1 - PASSKEY AUTOFILL (Config\PasskeyMfa::$enablePasskeyAutofill).
 *   The browser offers the visitor's passkeys in the email field's own
 *   autofill dropdown, next to any saved usernames - the "conditional UI"
 *   / "conditional mediation" flow described at
 *   https://developer.chrome.com/docs/identity/webauthn-conditional-ui and
 *   used by webauthn.io. Picking a passkey there signs the visitor in; a
 *   visitor who ignores it just types their email and password as usual.
 *   NOTHING POPS UP ON ITS OWN: the request sits quietly in the background
 *   until the visitor chooses a passkey from the dropdown, so it can never
 *   race a click on the normal login button or leave a prompt on the next
 *   page. (This replaces an earlier "prompt when the email field loses
 *   focus" feature, which could do both - see the README.)
 *
 * FEATURE 2 - "LOGIN WITH A PASSKEY" BUTTON
 *   (Config\PasskeyMfa::$enableDiscoverableAuthentication).
 *   Clicking the button opens the browser's own passkey picker straight
 *   away, for visitors who prefer a button or whose browser doesn't
 *   support autofill.
 *
 * Both features use the same two endpoints (routes-snippet.php:
 * passkey-discoverable-auth-options / -verify) and both need DISCOVERABLE
 * passkeys - the browser has to find the visitor's passkey without being
 * told who they are. Passkeys saved to a platform or password manager
 * (Windows Hello, iCloud Keychain, Google Password Manager, 1Password,
 * ...) are discoverable; see Config\PasskeyMfa::$residentKeyRequirement
 * for what this package asks for at registration.
 *
 * ONE CEREMONY AT A TIME: a browser allows only one passkey request in
 * flight. Clicking the button cancels the background autofill request
 * first, and restarts it afterwards if the visitor is still on the page.
 *
 * CSRF TOKEN HANDLING: CodeIgniter replaces the CSRF token after every
 * checked POST (Config\Security::$regenerate, true by default). Every
 * endpoint here returns the new token; this script writes it back into
 * the page's hidden CSRF field, so later requests - including the normal
 * password login - send a current token. The autofill request fetches its
 * options as the page loads; if the visitor submits the login form before
 * that fetch has returned, the submission is held until the fresh token is
 * in the form (at most SUBMIT_HOLD_MAX_MS), then sent.
 *
 * IF NOTHING HAPPENS AT ALL (no passkeys offered, no errors): check
 * app/Config/Filters.php's $globals for a login-required filter (e.g.
 * 'session'). If it's applied globally, its 'except' list must cover the
 * two routes below, or the filter redirects them to the login page and
 * this script receives HTML where it expected JSON. The routes-snippet.php
 * defaults live under auth/a/..., which many Shield apps already exclude.
 */
(function () {
    'use strict';

    // ---- Adjust these to match your login page ------------------------------

    // Must match Config\Security::$tokenName (CodeIgniter's default shown).
    var CSRF_FIELD_NAME = 'csrf_test_name';

    // The login form's email (or username) field - Feature 1 offers passkeys
    // in this field's autofill. The script adds the "webauthn" token to its
    // autocomplete attribute if it's missing (e.g. "email" becomes
    // "email webauthn"); putting it in your markup yourself is equally fine.
    var EMAIL_FIELD_SELECTOR = 'input[name="email"]';

    // Feature 2's button and an optional element for status messages.
    var BUTTON_SELECTOR = '#passkey-discoverable-login';
    var STATUS_SELECTOR = '#passkey-discoverable-status';

    // Change these if you changed the routes in routes-snippet.php.
    var OPTIONS_URL = '/auth/a/passkey-discoverable/options';
    var VERIFY_URL  = '/auth/a/passkey-discoverable/verify';

    // How long the button's picker may stay open before this page gives up
    // and re-enables itself. Choosing a passkey the site doesn't know can
    // leave some browsers waiting for minutes - see the README.
    var BUTTON_TIMEOUT_MS = 20000;

    // Longest a login-form submission is held while an options request is
    // still on its way back (see "CSRF TOKEN HANDLING").
    var SUBMIT_HOLD_MAX_MS = 10000;

    // -------------------------------------------------------------------------

    var emailField = document.querySelector(EMAIL_FIELD_SELECTOR);
    var button     = document.querySelector(BUTTON_SELECTOR);
    var statusEl   = document.querySelector(STATUS_SELECTOR);
    var loginForm  = emailField ? emailField.form : null;

    if (typeof window.PublicKeyCredential === 'undefined') {
        if (button) {
            button.style.display = 'none';
        }

        return; // No WebAuthn support - leave the page exactly as it is.
    }

    // The CSRF token as far as this script knows - null until the first
    // response arrives, in which case the page's hidden field is used.
    var currentCsrfValue = null;

    // Set once the normal login form has been submitted - nothing new is
    // started after that.
    var formSubmitted = false;

    // The AbortController for the background autofill request, while one
    // is running.
    var autofillController = null;

    // True while the button's picker is open.
    var buttonInProgress = false;

    // Settles when every options request currently in flight has returned
    // (and written its fresh CSRF token into the form); null when none is.
    var pendingOptions = null;

    // ---- CSRF helpers ----------------------------------------------------------

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

    // ---- Server calls ------------------------------------------------------------

    // Never aborted part-way: once this POST reaches the server it has used
    // up the page's CSRF token, and the fresh one only arrives in its
    // response - cancelling it would leave the page with no valid token.
    // Callers that no longer want the result simply ignore it. Waits for any
    // options request already in flight first, so it sends the newest token.
    async function fetchOptions() {
        if (pendingOptions !== null) {
            await pendingOptions;
        }

        var request = fetch(OPTIONS_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: csrfBodyParam(),
        }).then(function (response) {
            if (!response.ok) {
                var error = new Error('Passkey login is not available (HTTP ' + response.status + ').');
                error.name = 'UnavailableError';
                throw error;
            }

            return response.json();
        }).then(function (data) {
            updateCsrfToken(data);

            return data;
        });

        trackPendingOptions(request);

        return request;
    }

    function trackPendingOptions(request) {
        var settled = request.then(function () {}, function () {});
        var tracker = pendingOptions === null ? settled : Promise.all([pendingOptions, settled]);

        pendingOptions = tracker;

        tracker.then(function () {
            if (pendingOptions === tracker) {
                pendingOptions = null;
            }
        });
    }

    // Not abortable either, for the same CSRF-token reason as fetchOptions().
    async function verifyCredential(credential) {
        var response = await fetch(VERIFY_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'credential=' + encodeURIComponent(JSON.stringify(credential.toJSON())) + '&' + csrfBodyParam(),
        });

        var data = await response.json();
        updateCsrfToken(data);

        return data;
    }

    function setStatus(message) {
        if (statusEl) {
            statusEl.textContent = message;
        }
    }

    // ---- Feature 1: passkey autofill ------------------------------------------------

    function ensureWebauthnAutocomplete(field) {
        var tokens = (field.getAttribute('autocomplete') || '').trim().split(/\s+/).filter(function (token) {
            return token !== '' && token.toLowerCase() !== 'webauthn';
        });

        if (tokens.length === 0 || tokens[0].toLowerCase() === 'on' || tokens[0].toLowerCase() === 'off') {
            tokens = ['username'];
        }

        tokens.push('webauthn');
        field.setAttribute('autocomplete', tokens.join(' '));
    }

    async function autofillSupported() {
        if (typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function') {
            return false;
        }

        try {
            return await PublicKeyCredential.isConditionalMediationAvailable();
        } catch (error) {
            return false;
        }
    }

    async function startAutofill() {
        if (!emailField || formSubmitted || buttonInProgress || autofillController !== null) {
            return;
        }

        if (!(await autofillSupported())) {
            return;
        }

        // Checked again: the button could have been clicked, or the form
        // submitted, while the support check above was awaited.
        if (formSubmitted || buttonInProgress || autofillController !== null) {
            return;
        }

        ensureWebauthnAutocomplete(emailField);

        var controller     = new AbortController();
        autofillController = controller;
        var offerAgain     = false;

        try {
            var optionsData = await fetchOptions();

            if (controller.signal.aborted || formSubmitted) {
                return;
            }

            var publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(optionsData.options);

            // Waits - with no prompt - until the visitor picks a passkey from
            // the email field's autofill dropdown, or until it's aborted.
            var credential = await navigator.credentials.get({
                mediation: 'conditional',
                publicKey: publicKey,
                signal: controller.signal,
            });

            autofillController = null;
            setStatus('');

            var result = await verifyCredential(credential);

            if (result.success) {
                window.location.href = result.redirect;

                return;
            }

            setStatus('Could not sign you in with that passkey. Please try again, or use your password instead.');

            // The visitor chose a passkey that didn't verify - offer passkeys
            // again so they can pick another one.
            offerAgain = true;
        } catch (error) {
            if (!error || error.name !== 'AbortError') {
                // Anything else (no network, feature switched off
                // server-side, a browser quirk) just leaves the page as a
                // normal password form - never retried automatically, so a
                // persistent failure can't loop.
                console.warn('Passkey autofill stopped (' + (error && error.name ? error.name : 'unknown error') + '):', error);
            }
        } finally {
            if (autofillController === controller) {
                autofillController = null;
            }
        }

        if (offerAgain) {
            startAutofill();
        }
    }

    function stopAutofill() {
        if (autofillController !== null) {
            autofillController.abort();
            autofillController = null;
        }
    }

    // ---- Feature 2: "Login with a passkey" button ------------------------------------

    async function signInWithButton() {
        if (buttonInProgress || formSubmitted) {
            return;
        }

        buttonInProgress = true;
        button.disabled  = true;
        setStatus('');

        // A browser allows one passkey request at a time.
        stopAutofill();

        var controller = new AbortController();
        var timeoutId  = setTimeout(function () {
            controller.abort();
        }, BUTTON_TIMEOUT_MS);

        var navigating = false;

        try {
            var optionsData = await fetchOptions();

            if (formSubmitted) {
                return;
            }

            if (controller.signal.aborted) {
                setStatus('That took too long - please try again, or use your password instead.');

                return;
            }

            var publicKey  = PublicKeyCredential.parseRequestOptionsFromJSON(optionsData.options);
            var credential = await navigator.credentials.get({
                publicKey: publicKey,
                signal: controller.signal,
            });

            var result = await verifyCredential(credential);

            if (result.success) {
                navigating = true;
                window.location.href = result.redirect;

                return;
            }

            setStatus('Could not sign you in with that passkey. Please try again, or use your password instead.');
        } catch (error) {
            if (error && error.name === 'AbortError') {
                setStatus('That took too long - please try again, or use your password instead.');
            } else if (error && error.name === 'UnavailableError') {
                setStatus('This login option is not currently available.');
            } else if (error && error.name !== 'NotAllowedError') {
                // NotAllowedError is the visitor cancelling the picker - no
                // message needed for that.
                setStatus('Something went wrong signing you in with a passkey. Please try again, or use your password instead.');
                console.warn('Passkey button sign-in failed:', error);
            }
        } finally {
            clearTimeout(timeoutId);
            buttonInProgress = false;
            button.disabled  = false;

            if (!navigating) {
                startAutofill();
            }
        }
    }

    // ---- The normal password login ---------------------------------------------------

    function isSubmitControlOf(element, form) {
        return !!element && element.form === form && (element.type === 'submit' || element.type === 'image');
    }

    function resubmit(form, submitter) {
        if (typeof form.requestSubmit === 'function') {
            try {
                form.requestSubmit(isSubmitControlOf(submitter, form) ? submitter : undefined);

                return;
            } catch (error) {
                // Fall back to submit() below.
            }
        }

        form.submit();
    }

    var submitHeld = false;

    if (loginForm) {
        loginForm.addEventListener('submit', function (event) {
            formSubmitted = true;
            stopAutofill();

            // An options request is still on its way back, and it has
            // already used up the token this form is about to send. Hold the
            // submission until the fresh token is in the form.
            if (pendingOptions !== null && !submitHeld) {
                event.preventDefault();
                submitHeld = true;

                var submitter = event.submitter || null;
                var timeout   = new Promise(function (resolve) {
                    setTimeout(resolve, SUBMIT_HOLD_MAX_MS);
                });

                Promise.race([pendingOptions, timeout]).then(function () {
                    resubmit(loginForm, submitter);
                });
            }
        });
    }

    // ---- Start up ----------------------------------------------------------------------

    if (button) {
        button.addEventListener('click', function (event) {
            event.preventDefault(); // in case the button sits inside the login form
            signInWithButton();
        });
    }

    // Coming back to the login page with the browser's Back button can
    // restore it from the page cache with this script's state intact -
    // reset it so autofill works again.
    window.addEventListener('pageshow', function (event) {
        if (event.persisted) {
            formSubmitted = false;
            submitHeld    = false;
            startAutofill();
        }
    });

    startAutofill();
})();
