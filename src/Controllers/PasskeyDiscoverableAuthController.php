<?php

declare(strict_types=1);

namespace PasskeyMfa\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\HTTP\ResponseInterface;
use Config\PasskeyMfa as PasskeyMfaConfig;
use PasskeyMfa\Libraries\CompletesEarlyLogin;
use PasskeyMfa\Libraries\PasskeyIdentityStore;

/**
 * Two AJAX (JSON) endpoints for passkey sign-in on the login page, used
 * by both of this package's optional login-page features:
 *
 *   - passkey autofill (Config\PasskeyMfa::$enablePasskeyAutofill): the
 *     browser offers the visitor's passkeys in the email field's autofill
 *     dropdown ("conditional UI");
 *   - the "Login with a passkey" button
 *     (Config\PasskeyMfa::$enableDiscoverableAuthentication).
 *
 * Neither needs an email or username up front: the browser shows
 * whichever discoverable passkeys it has for this site, and the server
 * identifies who signed in from whichever one they choose. Both endpoints
 * return 404 unless at least one of the two options is on. See the
 * README's "Optional: passkey sign-in on the login page", and
 * passkey-login.js, for the page side.
 *
 * See PasskeyIdentityStore::beginDiscoverableAuthentication()/
 * completeDiscoverableAuthentication() for the WebAuthn and security
 * design - notably, the resolved user comes from this server's own
 * trusted credential_id lookup, confirmed by the signature check, never
 * from trusting the assertion's own userHandle field directly.
 *
 * REQUIRES DISCOVERABLE CREDENTIALS: a passkey is only offered in this
 * flow if it was registered as "discoverable" (a.k.a. "resident key") -
 * see Config\PasskeyMfa::$residentKeyRequirement. Already-registered
 * passkeys may or may not qualify, depending on what the authenticator
 * chose at the time; this package can't detect that for existing
 * credentials.
 */
class PasskeyDiscoverableAuthController extends Controller
{
    use CompletesEarlyLogin;

    private PasskeyMfaConfig $config;
    private PasskeyIdentityStore $store;

    public function __construct()
    {
        $this->config = config('PasskeyMfa');
        $this->store  = new PasskeyIdentityStore();
    }

    /**
     * No email/username parameter at all, deliberately - see this
     * class's own doc comment. Always returns options when enabled: no
     * user has been identified yet, so the browser's own picker (or
     * autofill list) is what decides whether the visitor has anything
     * usable, not this endpoint. Revealing nothing about accounts also
     * means it can't be used to probe which emails are registered.
     */
    public function options(): ResponseInterface
    {
        if (! $this->isEnabled()) {
            return $this->response->setStatusCode(404);
        }

        $optionsJson = $this->store->beginDiscoverableAuthentication();

        // Embeds the raw options JSON string directly rather than
        // decoding it and letting setJSON() re-encode it. A decode/
        // re-encode round trip in an earlier login-page feature broke
        // sign-in once a user had more than one passkey registered (a
        // generic "problem signing you in" error in Edge), while the MFA
        // challenge page, which embeds the raw string, kept working.
        $body = '{"options":' . $optionsJson
            . ',"csrfName":' . json_encode(csrf_token())
            . ',"csrfHash":' . json_encode(csrf_hash()) . '}';

        return $this->response->setContentType('application/json')->setBody($body);
    }

    public function verify(): ResponseInterface
    {
        if (! $this->isEnabled()) {
            return $this->response->setStatusCode(404);
        }

        $responseJson = (string) $this->request->getPost('credential');

        $user = $responseJson === '' ? null : $this->store->completeDiscoverableAuthentication($responseJson);

        if ($user === null) {
            return $this->response->setJSON([
                'success'  => false,
                'csrfName' => csrf_token(),
                'csrfHash' => csrf_hash(),
            ])->setStatusCode(401);
        }

        $mfaTriggered = $this->completeEarlyLogin($user, $this->config->earlyAuthenticationIsSufficient);

        return $this->response->setJSON([
            'success'  => true,
            'redirect' => $mfaTriggered ? route_to('auth-action-show') : config('Auth')->loginRedirect(),
        ]);
    }

    /**
     * Either login-page option uses these endpoints - see this class's
     * own doc comment.
     */
    private function isEnabled(): bool
    {
        return $this->config->enablePasskeyAutofill || $this->config->enableDiscoverableAuthentication;
    }
}
