<?php

declare(strict_types=1);

namespace PasskeyMfa\Authentication\Actions;

use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\Response;
use CodeIgniter\Shield\Authentication\Actions\ActionInterface;
use CodeIgniter\Shield\Authentication\Actions\ConditionalActionInterface;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Exceptions\RuntimeException;
use Config\PasskeyMfa as PasskeyMfaConfig;
use PasskeyMfa\Libraries\CompletesPendingAction;
use PasskeyMfa\Libraries\DiagnosticLog;
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
 *
 * IMPLEMENTS ConditionalActionInterface - CONFIRMED, REAL BUG FIXED
 * HERE: a real report showed a user who already had a registered,
 * enrolled passkey still being routed into THIS class's enrollment
 * flow on a later, ordinary login attempt (register=PasskeyActivator,
 * login=MfaDispatcher) - despite shield-mfa-dispatcher's own
 * MfaDispatcher::resolveRequiredMethod() correctly resolving
 * isEnrolled() to true for that user, confirmed via that package's own
 * diagnostic logging. Direct-URI and log-based tracing confirmed
 * MfaDispatcher::show() (the 'login' slot) never ran at all for that
 * request - only THIS class's show() (the 'register' slot) did,
 * meaning Shield itself decided the register slot was still the
 * pending one.
 *
 * Confirmed against Shield's own official documentation on Auth
 * Actions: a custom action can implement ConditionalActionInterface's
 * appliesTo(User $user): bool to tell Shield directly whether it
 * should be considered pending for a given user at all - "when
 * appliesTo() returns false, Shield does not start the action and
 * ignores stored identities for that action while the condition
 * remains false." Without this, Shield apparently still discovers a
 * "pending" register action for a user with a permanent, matching
 * passkey identity even when they've already completed registration
 * long ago and are now simply logging in again - PasskeyActivator and
 * PasskeyMfa share the same underlying identity type by design (see
 * this file's own doc comment above), so the mere existence of that
 * identity was apparently enough to make Shield treat 'register' as
 * still relevant, ahead of 'login', for every subsequent login
 * indefinitely.
 *
 * appliesTo() below returns false once the user already has a
 * registered passkey, which - per Shield's own documented behavior -
 * should stop Shield from ever treating this action as pending for
 * them again. This is a strong, evidence-based fix, not a fully
 * root-caused one: Shield's own internal slot-selection mechanism
 * beyond appliesTo() was not directly inspected (no access to Shield's
 * own source in this package's own development environment) - if this
 * doesn't fully resolve the behavior, that internal mechanism is the
 * next thing to investigate.
 */
class PasskeyActivator implements ActionInterface, ConditionalActionInterface
{
    use CompletesPendingAction;

    protected PasskeyIdentityStore $store;
    protected PasskeyMfaConfig $config;

    public function __construct()
    {
        $this->store  = new PasskeyIdentityStore();
        $this->config = config('PasskeyMfa');
    }

    /**
     * {@inheritDoc}
     *
     * Confirmed via Shield's own docs: "may be called more than once
     * while Shield checks for actions, so keep it deterministic, free
     * of side effects, and fail closed when the condition cannot be
     * determined." hasEnrolled() is a plain, read-only DB check - no
     * side effects, and deterministic for a given user's stored state.
     * "Fail closed" here means: if this can't be determined for some
     * reason, this method should lean toward NOT applying (false)
     * rather than forcing enrollment on someone who may already be
     * enrolled - hasEnrolled() itself doesn't throw under normal
     * conditions, so this doesn't need its own additional guard beyond
     * that.
     */
    public function appliesTo(User $user): bool
    {
        return ! $this->store->hasEnrolled($user);
    }

    /**
     * TEMPORARY DIAGNOSTIC LOGGING added below - part of a live
     * investigation (see shield-mfa-dispatcher's own MfaDispatcher/
     * MethodEnrollmentChecker diagnostic logging) into a real report:
     * a user who is confirmed (via that other logging) to already be
     * enrolled in passkey still saw the ENROLLMENT prompt on a
     * subsequent login, despite MfaDispatcher::resolveRequiredMethod()
     * correctly resolving isEnrolled() to true for them. This logs
     * user_id and the current URI whenever this method runs, so we can
     * confirm directly whether Shield is invoking THIS action (the
     * 'register' slot) during what should be a normal login attempt -
     * which would point at Shield's own action-slot resolution, not
     * this package's or shield-mfa-dispatcher's own enrollment logic
     * (already confirmed correct). Gated to only ever write when
     * ENVIRONMENT is 'development' (see DiagnosticLog's own doc
     * comment) so this never accumulates user_id values in a
     * production log from ordinary registrations.
     */
    public function show(): string
    {
        $user = $this->getPendingUser();

        DiagnosticLog::write(
            'info',
            'PasskeyActivator show(): running for user_id {user_id}, current URI {uri}.',
            ['user_id' => $user->id, 'uri' => (string) current_url(true)]
        );

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
