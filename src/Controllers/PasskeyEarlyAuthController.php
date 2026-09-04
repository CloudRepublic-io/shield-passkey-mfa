<?php

declare(strict_types=1);

namespace PasskeyMfa\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;
use Config\PasskeyMfa as PasskeyMfaConfig;
use PasskeyMfa\Libraries\PasskeyIdentityStore;
use ReflectionObject;

/**
 * Two AJAX (JSON) endpoints for a login page's own JavaScript to call
 * BEFORE the login form is even submitted - typically wired to fire on
 * blur of the email field, so a returning user with a registered
 * passkey gets the browser's native passkey prompt immediately,
 * without ever needing to type a password. Off entirely unless
 * Config\PasskeyMfa::$enableEarlyAuthentication is true - see that
 * property's own doc comment, and "Optional: trigger a passkey prompt
 * from the login form" in the README, for the full picture including
 * the example JavaScript this package ships.
 *
 * DISTINCT FROM PasskeyMfa (the login Action) AND PasskeyStepUpController:
 * neither Shield's pending-login machinery nor an already-logged-in
 * session is involved here at all - this runs BEFORE any of that,
 * against a user identified only by whatever email the visitor just
 * typed. Reuses PasskeyIdentityStore::beginAuthentication()/completeAuthentication()
 * directly, the same WebAuthn ceremony every other flow in this
 * package uses - just invoked against a User looked up by email
 * rather than one Shield has already put in a pending or logged-in
 * state.
 *
 * EMAIL ENUMERATION: options() deliberately returns the SAME
 * {"available": false} response whether the email doesn't exist at
 * all, or exists but has no registered passkey - the two cases are
 * indistinguishable from the outside, so this endpoint can't be used
 * to probe which email addresses have accounts.
 *
 * SESSION-PINNED EMAIL: options() stashes the email a challenge was
 * issued for in session; verify() re-derives the user from THAT, not
 * from anything the client sends at verify time - a tampered
 * client-side email can't be used to complete a DIFFERENT user's
 * challenge than the one that was actually issued.
 */
class PasskeyEarlyAuthController extends Controller
{
    private const SESSION_EMAIL_KEY = 'passkey_early_auth_email';

    private PasskeyMfaConfig $config;
    private PasskeyIdentityStore $store;

    public function __construct()
    {
        $this->config = config('PasskeyMfa');
        $this->store  = new PasskeyIdentityStore();
    }

    public function options(): ResponseInterface
    {
        if (! $this->config->enableEarlyAuthentication) {
            return $this->response->setStatusCode(404);
        }

        $email = trim((string) $this->request->getPost('email'));
        $user  = $email === '' ? null : $this->findUserByEmail($email);

        if ($user === null || ! $this->store->hasEnrolled($user)) {
            return $this->response->setJSON(['available' => false]);
        }

        $optionsJson = $this->store->beginAuthentication($user);
        session()->set(self::SESSION_EMAIL_KEY, $email);

        return $this->response->setJSON([
            'available' => true,
            'options'   => json_decode($optionsJson, true),
        ]);
    }

    public function verify(): ResponseInterface
    {
        if (! $this->config->enableEarlyAuthentication) {
            return $this->response->setStatusCode(404);
        }

        $email = session(self::SESSION_EMAIL_KEY);
        session()->remove(self::SESSION_EMAIL_KEY);

        $user         = is_string($email) ? $this->findUserByEmail($email) : null;
        $responseJson = (string) $this->request->getPost('credential');

        if ($user === null || $responseJson === '' || ! $this->store->completeAuthentication($user, $responseJson)) {
            return $this->response->setJSON(['success' => false])->setStatusCode(401);
        }

        $mfaTriggered = $this->completeLogin($user);

        return $this->response->setJSON([
            'success'  => true,
            'redirect' => $mfaTriggered ? route_to('auth-action-show') : config('Auth')->loginRedirect(),
        ]);
    }

    private function findUserByEmail(string $email): ?User
    {
        return model(UserModel::class)->findByCredentials(['email' => $email]);
    }

    /**
     * Logs the given, already-fully-verified user in. If
     * $earlyAuthenticationIsSufficient is on (the default), this is a
     * normal, complete login. Otherwise, the user is put into the same
     * "pending MFA" state a real Session::attempt() would have left
     * them in, and the JSON response's own "redirect" points at the
     * MFA challenge page instead of the app's normal post-login
     * destination.
     *
     * Uses the identical reflection-based mechanism
     * shield-oauth-login's own OAuthLoginController::completeLogin()
     * needed for the exact same underlying reason - see that class's
     * doc comment for the full explanation (summarized here since this
     * package hits the identical gap): Shield's own Session::attempt()
     * is the only path that correctly triggers its PRIVATE
     * setAuthAction() pending-check, and attempt() requires a password
     * to check, which a passkey-authenticated visitor at THIS point
     * doesn't have (they haven't submitted the login form at all yet).
     * There is no public Shield API for "log this already-verified
     * user in, but still check whether MFA should apply first." If a
     * future Shield version changes $userState's internal
     * representation, this is the method that needs revisiting;
     * nothing else in this controller depends on it.
     *
     * @return bool True if MFA was triggered (the caller should send
     *              the browser to the MFA challenge page, not the
     *              app's normal post-login destination).
     */
    private function completeLogin(User $user): bool
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        if ($this->config->earlyAuthenticationIsSufficient || ! $this->hasConfiguredLoginAction()) {
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

        $field                        = setting('Auth.sessionConfig')['field'];
        $data                         = session($field) ?? [];
        $data['id']                   = $user->id;
        $data['auth_action']          = $loginAction;
        $data['auth_action_message']  = null;
        session()->set($field, $data);

        return true;
    }

    private function hasConfiguredLoginAction(): bool
    {
        $action = config('Auth')->actions['login'] ?? null;

        return $action !== null && $action !== '';
    }
}
