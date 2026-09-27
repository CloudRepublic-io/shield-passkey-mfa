<?php
/**
 * Add these to app/Config/Routes.php. Shield doesn't know about these
 * controllers/routes, so they need to be added by hand.
 */

// The "skip for now" link on PasskeyActivator's enrollment view. This is
// NOT wrapped in the 'session' filter (or any full-login-required
// filter) - it's reached by a user who is mid-registration (Shield's
// "pending" state), not someone already fully logged in. Wrapping it
// in a filter that requires full login would make it unreachable.
//
// Points at PasskeyActivatorController, NOT at PasskeyActivator (the
// Action class) directly - routes are dispatched through CodeIgniter's
// Controller lifecycle (initController(), etc.), which an
// ActionInterface implementation doesn't have.
$routes->post(
    'auth/a/passkey-activator/skip',
    '\PasskeyMfa\Controllers\PasskeyActivatorController::skip',
    ['as' => 'passkey-activator-skip']
);

// OPTIONAL - only needed if Config\PasskeyMfa::$enablePasskeyAutofill or
// $enableDiscoverableAuthentication is turned on (both use these two
// routes). Both return 404 on their own while both flags are off, so adding
// them early is harmless. See "Optional: passkey sign-in on the login page"
// in the README.
//
// Deliberately public (NOT wrapped in the 'session' filter or any
// login-required filter): they're called from the login page before the
// visitor is authenticated - no user is known when options() is called,
// and verify() is what determines who logged in.
//
// Deliberately placed under auth/a/... - Shield's own convention for its
// gateway-action routes, and commonly already excluded from a global
// login-required filter (e.g. 'except' => ['auth/a/*'] in
// app/Config/Filters.php). A real app's global filter once intercepted
// login-page passkey routes placed elsewhere, redirecting them to the
// login page instead of reaching the controller. If your app excludes
// something other than auth/a/*, add these two routes to your own list.
$routes->post(
    'auth/a/passkey-discoverable/options',
    '\PasskeyMfa\Controllers\PasskeyDiscoverableAuthController::options',
    ['as' => 'passkey-discoverable-auth-options']
);

$routes->post(
    'auth/a/passkey-discoverable/verify',
    '\PasskeyMfa\Controllers\PasskeyDiscoverableAuthController::verify',
    ['as' => 'passkey-discoverable-auth-verify']
);

// These are for an already-fully-logged-in user managing their own
// passkeys, so the 'session' filter is correct here.
$routes->group('', ['filter' => 'session'], static function ($routes) {
    $routes->get(
        'account/passkeys',
        '\PasskeyMfa\Controllers\PasskeySettingsController::index',
        ['as' => 'passkey-settings']
    );

    $routes->get(
        'account/passkeys/enroll',
        '\PasskeyMfa\Controllers\PasskeySettingsController::enroll',
        ['as' => 'passkey-settings-enroll']
    );

    $routes->post(
        'account/passkeys/confirm',
        '\PasskeyMfa\Controllers\PasskeySettingsController::confirm',
        ['as' => 'passkey-settings-confirm']
    );

    $routes->post(
        'account/passkeys/(:num)/rename',
        '\PasskeyMfa\Controllers\PasskeySettingsController::rename/$1',
        ['as' => 'passkey-settings-rename']
    );

    $routes->post(
        'account/passkeys/(:num)/delete',
        '\PasskeyMfa\Controllers\PasskeySettingsController::delete/$1',
        ['as' => 'passkey-settings-delete']
    );

    // Step-up challenge shown by the RequireFreshPasskey filter.
    // Wrapped in the 'session' filter here too - this challenges an
    // EXISTING, already-logged-in session, it doesn't log anyone in, so
    // it makes no sense to reach without already being logged in.
    $routes->get(
        'account/passkeys/step-up',
        '\PasskeyMfa\Controllers\PasskeyStepUpController::show',
        ['as' => 'passkey-step-up']
    );

    $routes->post(
        'account/passkeys/step-up',
        '\PasskeyMfa\Controllers\PasskeyStepUpController::verify',
        ['as' => 'passkey-step-up-verify']
    );
});
