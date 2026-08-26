<?php

declare(strict_types=1);

namespace PasskeyMfa\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\HTTP\RedirectResponse;
use Config\PasskeyMfa as PasskeyMfaConfig;
use PasskeyMfa\Libraries\PasskeyIdentityStore;

/**
 * Lets an already-logged-in user see, add, rename, and remove their
 * own passkeys - unlike TotpSettingsController (a single on/off
 * secret), this manages a genuine list, since a user can register
 * several passkeys (phone, laptop, a hardware key as backup).
 */
class PasskeySettingsController extends Controller
{
    protected PasskeyIdentityStore $store;
    protected PasskeyMfaConfig $config;

    public function __construct()
    {
        $this->store  = new PasskeyIdentityStore();
        $this->config = config('PasskeyMfa');
    }

    public function index(): string
    {
        $user = auth()->user();

        return view($this->config->views['passkey_settings_index'], [
            'credentials' => $this->store->listCredentials($user),
        ]);
    }

    public function enroll(): string
    {
        $user = auth()->user();

        $optionsJson = $this->store->beginRegistration($user, $user->email ?? ('user-' . $user->id));

        return view($this->config->views['passkey_settings_enroll'], [
            'optionsJson' => $optionsJson,
        ]);
    }

    public function confirm(): RedirectResponse
    {
        $user         = auth()->user();
        $responseJson = (string) $this->request->getPost('credential');
        $label        = trim((string) $this->request->getPost('device_name'));

        if ($responseJson === '' || ! $this->store->completeRegistration($user, $responseJson, $label !== '' ? $label : null)) {
            return redirect()->back()->with('error', lang('PasskeyMfa.registrationFailed'));
        }

        return redirect()->route('passkey-settings')->with('message', lang('PasskeyMfa.addedMessage'));
    }

    public function rename(int $id): RedirectResponse
    {
        $user = auth()->user();
        $name = trim((string) $this->request->getPost('name'));

        if ($name === '') {
            return redirect()->back()->with('error', lang('PasskeyMfa.nameRequired'));
        }

        $this->store->renameCredential($user, $id, $name);

        return redirect()->route('passkey-settings')->with('message', lang('PasskeyMfa.renamedMessage'));
    }

    public function delete(int $id): RedirectResponse
    {
        $user = auth()->user();

        $this->store->removeCredential($user, $id);

        return redirect()->route('passkey-settings')->with('message', lang('PasskeyMfa.removedMessage'));
    }
}
