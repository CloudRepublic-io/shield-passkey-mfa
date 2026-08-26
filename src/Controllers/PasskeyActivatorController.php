<?php

declare(strict_types=1);

namespace PasskeyMfa\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Exceptions\RuntimeException;
use PasskeyMfa\Libraries\CompletesPendingAction;
use PasskeyMfa\Libraries\PasskeyIdentityStore;

/**
 * Handles the "skip for now" link on PasskeyActivator's enrollment
 * view.
 *
 * This has to be a real Controller, not a method on PasskeyActivator
 * itself: routes are dispatched through CodeIgniter's normal
 * Controller lifecycle (which calls initController() on whatever class
 * is routed to), and PasskeyActivator - a Shield ActionInterface
 * implementation - doesn't extend Controller and has no such method.
 * show()/handle()/verify() on Action classes are only ever called
 * indirectly, by Shield's own ActionController, which is why they
 * don't hit this problem; a route pointed directly at an Action class
 * does (confirmed the hard way while building the shield-totp-mfa
 * package this one is modeled on: "Call to undefined method
 * ...::initController()").
 */
class PasskeyActivatorController extends Controller
{
    use CompletesPendingAction;

    public function skip(): RedirectResponse
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();
        $user          = $authenticator->getPendingUser();

        if ($user === null) {
            throw new RuntimeException('PasskeyActivatorController: cannot get the pending registration user.');
        }

        (new PasskeyIdentityStore())->cancelRegistration();

        $this->completePendingAction($user);

        $authenticator->getUser()->activate();

        return redirect()->to(config('Auth')->registerRedirect());
    }
}
