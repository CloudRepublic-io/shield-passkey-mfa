<?php

declare(strict_types=1);

namespace PasskeyMfa\Libraries;

use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Entities\User;
use ReflectionObject;

/**
 * Used by PasskeyDiscoverableAuthController, which completes a login for a
 * user verified entirely outside Shield's own Session::attempt() flow (no
 * password was ever checked - it only runs after a passkey ceremony has
 * already succeeded, from either passkey autofill or the "Login with a
 * passkey" button).
 */
trait CompletesEarlyLogin
{
    /**
     * Logs the given, already-fully-verified user in. If
     * $earlyAuthenticationIsSufficient is on (the default), this is a normal, complete login.
     * Otherwise, the user is put into the same "pending MFA" state a
     * real Session::attempt() would have left them in, and the caller
     * should send the browser to the MFA challenge page instead of the
     * app's normal post-login destination.
     *
     * Uses the identical reflection-based mechanism
     * shield-oauth-login's own OAuthLoginController::completeLogin()
     * needed for the exact same underlying reason - see that class's
     * doc comment for the full explanation (summarized here since this
     * package hits the identical gap): Shield's own Session::attempt()
     * is the only path that correctly triggers its PRIVATE
     * setAuthAction() pending-check, and attempt() requires a password
     * to check, which a visitor at this point in either flow doesn't
     * have. There is no public Shield API for "log this
     * already-verified user in, but still check whether MFA should
     * apply first." If a future Shield version changes $userState's
     * internal representation, this is the method that needs
     * revisiting; nothing else depends on it.
     *
     * @return bool True if MFA was triggered (the caller should send
     *              the browser to the MFA challenge page, not the
     *              app's normal post-login destination).
     */
    private function completeEarlyLogin(User $user, bool $earlyAuthenticationIsSufficient): bool
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        if ($earlyAuthenticationIsSufficient || ! $this->hasConfiguredLoginAction()) {
            $authenticator->login($user);

            return false;
        }

        $loginAction = config('Auth')->actions['login'];
        $action      = new $loginAction();

        $action->createIdentity($user);

        $reflection = new ReflectionObject($authenticator);

        $userStateProperty = $reflection->getProperty('userState');
        $userStateProperty->setAccessible(true);
        $userStateProperty->setValue($authenticator, 2); // STATE_PENDING - see this method's own doc comment

        $userProperty = $reflection->getProperty('user');
        $userProperty->setAccessible(true);
        $userProperty->setValue($authenticator, $user);

        $field                       = setting('Auth.sessionConfig')['field'];
        $data                        = session($field) ?? [];
        $data['id']                  = $user->id;
        $data['auth_action']         = $loginAction;
        $data['auth_action_message'] = null;
        session()->set($field, $data);

        return true;
    }

    private function hasConfiguredLoginAction(): bool
    {
        $action = config('Auth')->actions['login'] ?? null;

        return $action !== null && $action !== '';
    }
}
