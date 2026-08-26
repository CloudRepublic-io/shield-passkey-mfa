<?php

declare(strict_types=1);

namespace PasskeyMfa\Libraries;

use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Entities\User;

/**
 * Shared "finish the pending action" logic - confirmed (across the
 * shield-totp-mfa and shield-whatsapp-mfa packages in this same
 * series) to require BOTH steps below, not completeLogin() alone:
 *
 *   1. Manually clear Shield's own pending-action session markers
 *      (auth_action / auth_action_message).
 *   2. Call completeLogin($user) - the method Shield's own
 *      Session::attempt() itself calls to finish a pending action
 *      (login() is a stricter, separate public method that refuses if
 *      identities still exist for the action type).
 */
trait CompletesPendingAction
{
    protected function clearAuthActionSession(): void
    {
        $field = setting('Auth.sessionConfig')['field'];

        $sessionUserInfo = session($field) ?? [];
        unset($sessionUserInfo['auth_action'], $sessionUserInfo['auth_action_message']);
        session()->set($field, $sessionUserInfo);
    }

    protected function completePendingAction(User $user): void
    {
        $this->clearAuthActionSession();

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();
        $authenticator->completeLogin($user);
    }
}
