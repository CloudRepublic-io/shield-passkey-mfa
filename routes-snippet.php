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

// OPTIONAL - only needed if Config\PasskeyMfa::$enableEarlyAuthentication
// is turned on. Deliberately public (NOT wrapped in the 'session' filter,
// or any full-login-required filter) - these are called from the login
// page itself, before the visitor is authenticated at all. Both routes
// return early (404) on their own if the config flag is off, so adding
// these routes without also flipping that flag is harmless. See
// "Optional: trigger a passkey prompt from the login form" in the README.
//
// Deliberately placed under auth/a/... - Shield's own established
// convention for its gateway-action routes (auth-action-show/handle/verify),
// which is ALSO commonly the exact pattern apps already exclude from any
// global login-required filter (e.g. 'except' => ['auth/a/*'] in
// app/Config/Filters.php). CONFIRMED, REAL ISSUE: an earlier version of
// this snippet used auth/passkey/early/... instead, which does NOT match
// that common exclusion pattern - a global filter silently intercepted
// both routes for a real app, redirecting them to the login page (a 303)
// instead of ever reaching this controller at all. If your own app's
// global filters exclude something OTHER than auth/a/*, these two routes
// still need to be added to whatever your own exclusion list actually is
// - check app/Config/Filters.php's $globals before assuming this "just
// works".
$routes->post(
    'auth/a/passkey-early/options',
    '\PasskeyMfa\Controllers\PasskeyEarlyAuthController::options',
    ['as' => 'passkey-early-auth-options']
);

$routes->post(
    'auth/a/passkey-early/verify',
    '\PasskeyMfa\Controllers\PasskeyEarlyAuthController::verify',
    ['as' => 'passkey-early-auth-verify']
);

// OPTIONAL - only needed if Config\PasskeyMfa::$enableDiscoverableAuthentication
// is turned on. Same deliberate placement under auth/a/... as the two
// routes above, for the identical reason - see the comment above these
// for the full explanation. Also deliberately public/unfiltered: no
// user is known at all when options() is called, and verify() is what
// determines who logged in, so neither can require an existing session.
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
