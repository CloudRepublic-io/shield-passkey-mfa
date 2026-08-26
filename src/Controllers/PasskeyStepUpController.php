<?php

declare(strict_types=1);

namespace PasskeyMfa\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\HTTP\RedirectResponse;
use Config\PasskeyMfa as PasskeyMfaConfig;
use PasskeyMfa\Libraries\PasskeyIdentityStore;

/**
 * The "please confirm it's you" page shown by the RequireFreshPasskey
 * filter when a protected route is reached without a recent-enough
 * step-up verification.
 *
 * Distinct from PasskeyMfa (the login action): this operates on an
 * already-fully-logged-in user (auth()->user()), not Shield's
 * "pending login" user - there is no Shield ActionInterface machinery
 * involved here at all, just an ordinary controller behind an ordinary
 * filter. See shield-totp-mfa's TotpStepUpController for the same
 * pattern applied to TOTP.
 *
 * Reuses PasskeyIdentityStore::beginAuthentication()/completeAuthentication()
 * directly - the exact same WebAuthn ceremony the login action itself
 * uses, since step-up genuinely is "log in again with your passkey",
 * just without going through Shield's pending-login machinery.
 */
class PasskeyStepUpController extends Controller
{
    protected PasskeyIdentityStore $store;
    protected PasskeyMfaConfig $config;

    public function __construct()
    {
        $this->store  = new PasskeyIdentityStore();
        $this->config = config('PasskeyMfa');
    }

    public function show(): string
    {
        $user        = auth()->user();
        $optionsJson = $this->store->beginAuthentication($user);

        return view($this->config->views['passkey_step_up'], [
            'optionsJson' => $optionsJson,
        ]);
    }

    public function verify(): RedirectResponse
    {
        $user         = auth()->user();
        $responseJson = (string) $this->request->getPost('credential');

        if ($responseJson === '' || ! $this->store->completeAuthentication($user, $responseJson)) {
            // Safe here (unlike WhatsApp's login-time verify()): this
            // page is reached via show(), a GET route, with no
            // separate "send" step in between the way WhatsApp's
            // handle() introduces - see shield-whatsapp-mfa's README
            // for the full explanation of why back() is unsafe there
            // specifically but not here.
            return redirect()->back()->with('error', lang('PasskeyMfa.stepUpFailed'));
        }

        session()->set($this->config->stepUpSessionKey, time());

        $redirectTo = session('passkey_step_up_redirect');
        session()->remove('passkey_step_up_redirect');

        // $redirectTo, when present, was captured by
        // RequireFreshPasskey from current_url() on this same site -
        // not user-supplied input - so this isn't an open-redirect
        // risk. Falls back to the app's normal post-login destination
        // if it's somehow missing (e.g. this page was reached directly
        // rather than via the filter).
        return redirect()->to($redirectTo ?: config('Auth')->loginRedirect());
    }
}
