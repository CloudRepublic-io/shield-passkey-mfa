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
 * Passkey (WebAuthn) login verification action for Shield.
 *
 *   public array $actions = [
 *       'register' => \PasskeyMfa\Authentication\Actions\PasskeyActivator::class, // optional
 *       'login'    => \PasskeyMfa\Authentication\Actions\PasskeyMfa::class,
 *   ];
 *
 * VERIFICATION ONLY - deliberately, for exactly the same reason as
 * shield-totp-mfa's TotpMfa: Shield decides whether an action is
 * "pending" purely by whether an identity of getType()'s type exists
 * in the database - not by anything about that identity's state. A
 * permanent credential marker that's never deleted (the whole point of
 * a passkey - it should keep working across logins) is only safe to
 * check for here because enrollment happens somewhere else entirely
 * (PasskeyActivator, or the settings page), using a *different*,
 * disposable identity type. See PasskeyIdentityStore's class doc
 * comment for the full explanation - this exact trap cost real,
 * working time to find when building the TOTP package this one is
 * modeled on; no need to repeat it here.
 *
 * Unlike TOTP, there's no code to type - the browser's WebAuthn API
 * handles proving possession of the private key. show() renders a page
 * whose JavaScript kicks off navigator.credentials.get() automatically
 * and posts the result to verify().
 */
class PasskeyMfa implements ActionInterface
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

        // Defensive only: Shield should never route here at all unless
        // a permanent marker already exists (see class doc comment).
        // If it somehow doesn't, there's nothing to challenge against.
        if (! $this->store->hasEnrolled($user)) {
            $this->completePendingAction($user);

            redirect()->to(config('Auth')->loginRedirect())->send();
            exit;
        }

        $optionsJson = $this->store->beginAuthentication($user);

        return view($this->config->views['passkey_mfa_verify'], [
            'optionsJson' => $optionsJson,
        ]);
    }

    /**
     * No "send" step for passkeys either, so this simply mirrors
     * show(). Exists in case Shield's ActionController expects
     * handle() to be reachable as a POST target in some flows.
     */
    public function handle(IncomingRequest $request): Response
    {
        return service('response')->setBody($this->show());
    }

    /**
     * TEMPORARY DIAGNOSTIC added at every step below - a real,
     * confirmed gap where a failed verification gave zero visibility
     * into WHERE in the flow it actually failed, and log_message()
     * alone turned out not to be reliably visible either (a real
     * report came back with nothing written to the app's own log at
     * all). The specific failure reason is now shown directly in the
     * page's own flash message too - guaranteed visible regardless of
     * the app's logging configuration, since it's the exact same
     * mechanism (session('error'), already rendered by
     * passkey_mfa_verify.php) that's already confirmed working.
     *
     * REVERT BEFORE LONG-TERM PRODUCTION USE: showing raw internal
     * failure reasons to end users is not something you'd normally
     * want permanently (see PasskeyIdentityStore::$lastFailureReason's
     * own doc comment) - this is deliberately verbose specifically to
     * get an open bug diagnosed, not a permanent UX choice.
     */
    public function verify(IncomingRequest $request): Response
    {
        $user         = $this->getPendingUser();
        $responseJson = (string) $request->getPost('credential');

        if ($responseJson === '') {
            log_message('error', 'PasskeyMfa verify: credential POST field was empty for user_id {user_id}.', ['user_id' => $user->id]);

            return redirect()->back()->with('error', lang('PasskeyMfa.verificationFailed') . ' [diagnostic: credential field was empty]');
        }

        if (! $this->store->completeAuthentication($user, $responseJson)) {
            $reason = $this->store->lastFailureReason ?? 'unknown - completeAuthentication() returned false with no reason recorded';
            log_message('error', 'PasskeyMfa verify: completeAuthentication() returned false for user_id {user_id}: {reason}', ['user_id' => $user->id, 'reason' => $reason]);

            return redirect()->back()->with('error', lang('PasskeyMfa.verificationFailed') . ' [diagnostic: ' . $reason . ']');
        }

        log_message('info', 'PasskeyMfa verify: completeAuthentication() succeeded for user_id {user_id}, completing login.', ['user_id' => $user->id]);

        $this->completePendingAction($user);

        return redirect()->to(config('Auth')->loginRedirect())
            ->with('message', lang('PasskeyMfa.successMessage'));
    }

    /**
     * Returns the permanent marker's type - safe here for the same
     * reason TotpMfa's genuine no-op createIdentity() is safe: by the
     * time Shield ever routes a login attempt to this class at all, a
     * permanent marker already exists (that's the only reason Shield's
     * own pending-check would have triggered this action).
     */
    public function getType(): string
    {
        return PasskeyIdentityStore::ID_TYPE_PASSKEY;
    }

    /** Genuine no-op - see class doc comment and getType() above. */
    public function createIdentity(User $user): string
    {
        return '';
    }

    protected function getPendingUser(): User
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();
        $user          = $authenticator->getPendingUser();

        if ($user === null) {
            throw new RuntimeException('PasskeyMfa: cannot get the pending login user.');
        }

        return $user;
    }
}
