<?php

declare(strict_types=1);

namespace PasskeyMfa\Authentication\Actions;

use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\Response;
use CodeIgniter\Shield\Authentication\Actions\ActionInterface;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Exceptions\RuntimeException;
use Config\PasskeyMfa as PasskeyMfaConfig;
use PasskeyMfa\Libraries\CompletesPendingAction;
use PasskeyMfa\Libraries\PasskeyIdentityStore;

/**
 * Optional passkey setup during registration. Register this as the
 * 'register' action if you want new users offered a passkey setup step
 * as part of signup:
 *
 *   public array $actions = [
 *       'register' => \PasskeyMfa\Authentication\Actions\PasskeyActivator::class,
 *       'login'    => \PasskeyMfa\Authentication\Actions\PasskeyMfa::class,
 *   ];
 *
 * OPTIONAL BY DESIGN: the enrollment view includes a "skip for now"
 * link, handled by PasskeyActivatorController::skip() (routes require a
 * real Controller, which this Action class is not - see that
 * controller's own doc comment) rather than a method on this class. A
 * user who skips is activated without a passkey, and can add one later
 * from the self-service settings page - or never, if they don't want
 * to. To make this mandatory instead, just remove the skip link/button
 * from the enrollment view.
 *
 * Writes to the exact same credentials table PasskeyMfa (the 'login'
 * action) reads from - see PasskeyIdentityStore, which is shared
 * between both, plus the self-service settings page.
 *
 * ALSO REUSED, unmodified, by shield-mfa-dispatcher's forced-setup
 * flow (Config\MfaDispatcher::$requiredMethodsForGroups) - see
 * TotpActivator's class doc comment (in shield-totp-mfa) for the full
 * explanation of the $user->active check in verify() below that makes
 * this safe.
 */
class PasskeyActivator implements ActionInterface
{
    use CompletesPendingAction;

    protected PasskeyIdentityStore $store;
    protected PasskeyMfaConfig $config;

    public function __construct()
    {
        $this->store  = new PasskeyIdentityStore();
        $this->config = config('PasskeyMfa');
    }

    public function show(): string
    {
        $user = $this->getPendingUser();

        $optionsJson = $this->store->beginRegistration($user, $user->email ?? ('user-' . $user->id));

        return view($this->config->views['passkey_activator_enroll'], [
            'optionsJson' => $optionsJson,
        ]);
    }

    /**
     * No "send" step, so this simply mirrors show(). Exists in case
     * Shield's ActionController expects handle() to be reachable as a
     * POST target in some flows.
     */
    public function handle(IncomingRequest $request): Response
    {
        return service('response')->setBody($this->show());
    }

    public function verify(IncomingRequest $request): Response
    {
        $user         = $this->getPendingUser();
        $responseJson = (string) $request->getPost('credential');
        $label        = trim((string) $request->getPost('device_name'));

        if ($responseJson === '' || ! $this->store->completeRegistration($user, $responseJson, $label !== '' ? $label : null)) {
            return redirect()->back()->with('error', lang('PasskeyMfa.registrationFailed'));
        }

        // Checked BEFORE completePendingAction()/activate() touch
        // anything - see the class doc comment for why this
        // distinguishes genuine registration from this same class
        // being reused as a forced-setup step during an existing
        // user's login (shield-mfa-dispatcher's
        // Config\MfaDispatcher::$requiredMethodsForGroups).
        $wasAlreadyActive = (bool) $user->active;

        $this->completePendingAction($user);

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        if (! $wasAlreadyActive) {
            $authenticator->getUser()->activate();

            return redirect()->to(config('Auth')->registerRedirect())
                ->with('message', lang('Auth.registerSuccess'));
        }

        // Reused as a login-time forced-setup step, not genuine
        // registration - the user was already active, so there's no
        // account to activate, and they should land wherever a normal
        // login sends them, not wherever a fresh registration does.
        return redirect()->to(config('Auth')->loginRedirect())
            ->with('message', lang('PasskeyMfa.successMessage'));
    }

    public function getType(): string
    {
        return PasskeyIdentityStore::ID_TYPE_PASSKEY_ACTIVATE;
    }

    /**
     * Ensures the disposable activation marker exists before Shield's
     * own pending-check runs immediately afterward - the actual
     * WebAuthn challenge is generated in show(), not here, since
     * that's where the real creation options are needed. This call is
     * idempotent-safe alongside show()'s own call.
     */
    public function createIdentity(User $user): string
    {
        $this->store->ensureActivationMarker($user);

        return 'passkey-registration-required';
    }

    protected function getPendingUser(): User
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();
        $user          = $authenticator->getPendingUser();

        if ($user === null) {
            throw new RuntimeException('PasskeyActivator: cannot get the pending registration user.');
        }

        return $user;
    }
}
