<?php

declare(strict_types=1);

namespace PasskeyMfa\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\HTTP\ResponseInterface;
use Config\PasskeyMfa as PasskeyMfaConfig;
use PasskeyMfa\Libraries\CompletesEarlyLogin;
use PasskeyMfa\Libraries\PasskeyIdentityStore;

/**
 * Two AJAX (JSON) endpoints for a "Login with a passkey" button on the
 * login page - unlike PasskeyEarlyAuthController, this needs no email
 * or username at all up front. The visitor clicks the button, the
 * browser's own passkey picker shows whichever discoverable
 * credentials it has for this site, and the server identifies who
 * they are from whichever one they choose. Off entirely unless
 * Config\PasskeyMfa::$enableDiscoverableAuthentication is true - see
 * that property's own doc comment, and "Optional: 'Login with a
 * passkey' button (no email needed)" in the README, for the full
 * picture including the example JavaScript this package ships.
 *
 * DISTINCT FROM PasskeyEarlyAuthController: that feature still needs a
 * known email to look up which credentials to offer
 * (allowCredentials); this one deliberately omits that entirely and
 * lets the browser show anything it has for this site, across every
 * account. See PasskeyIdentityStore::beginDiscoverableAuthentication()/
 * completeDiscoverableAuthentication()'s own doc comments for the full
 * WebAuthn and security design detail - notably, the resolved user's
 * identity comes from this server's own trusted credential_id lookup,
 * confirmed only afterward by the cryptographic signature check, never
 * from trusting the assertion response's own userHandle field
 * directly.
 *
 * REQUIRES DISCOVERABLE CREDENTIALS: a passkey only shows up in the
 * browser's own picker for this flow if it was registered as
 * "discoverable" (a.k.a. "resident key") in the first place - see
 * Config\PasskeyMfa::$residentKeyRequirement's own doc comment. Already-
 * registered passkeys may or may not qualify, depending entirely on
 * what the authenticator chose to do at the time - this package cannot
 * detect or guarantee this either way for existing credentials.
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
     * class's own doc comment. Always returns options when the feature
     * is enabled; there's no "available: false" case the way
     * PasskeyEarlyAuthController has, since no candidate user has been
     * identified yet to check enrollment against - the browser's own
     * picker is what determines whether the visitor has anything
     * usable, not this endpoint.
     */
    public function options(): ResponseInterface
    {
        if (! $this->config->enableDiscoverableAuthentication) {
            return $this->response->setStatusCode(404);
        }

        $optionsJson = $this->store->beginDiscoverableAuthentication();

        // Embeds the raw options JSON string directly rather than
        // decoding and letting setJSON() re-encode it - see
        // PasskeyEarlyAuthController::options()'s own doc comment for
        // the confirmed, real bug this avoids repeating here.
        $body = '{"options":' . $optionsJson
            . ',"csrfName":' . json_encode(csrf_token())
            . ',"csrfHash":' . json_encode(csrf_hash()) . '}';

        return $this->response->setContentType('application/json')->setBody($body);
    }

    public function verify(): ResponseInterface
    {
        if (! $this->config->enableDiscoverableAuthentication) {
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
}
