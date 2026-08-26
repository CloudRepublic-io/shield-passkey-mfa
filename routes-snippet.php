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
