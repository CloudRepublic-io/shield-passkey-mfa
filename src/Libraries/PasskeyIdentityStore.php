<?php

declare(strict_types=1);

namespace PasskeyMfa\Libraries;

use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use Config\PasskeyMfa as PasskeyMfaConfig;
use PasskeyMfa\Models\PasskeyCredentialModel;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * All passkey registration/verification logic lives here, used by
 * three entry points, the same shape as TotpIdentityStore in the
 * shield-totp-mfa package:
 *
 *   - PasskeyMfa (the 'login' action) - verification only.
 *   - PasskeyActivator (the 'register' action) - registration-time setup.
 *   - PasskeySettingsController - self-service management for existing
 *     users (add a passkey, name it, remove it) any time.
 *
 * TWO IDENTITY TYPES ARE USED, FOR THE SAME REASON AS TotpIdentityStore:
 *
 *   - self::ID_TYPE_PASSKEY ('passkey') - a permanent marker meaning
 *     "this user has at least one registered passkey", kept in sync
 *     with the real credential rows (created when the first credential
 *     is added, removed when the last one is removed). Never touched
 *     by the login action's createIdentity().
 *   - self::ID_TYPE_PASSKEY_ACTIVATE ('passkey_activate') - a
 *     short-lived marker that exists only during a registration
 *     ceremony, used purely so Shield's own pending-action check
 *     (which looks at whether *an identity of getType()'s type exists
 *     at all*, not at its content) has something to find during
 *     registration. Deleted the moment registration succeeds.
 *
 * The actual credential data (public key, credential ID, sign count)
 * lives in its own table (auth_passkey_credentials via
 * PasskeyCredentialModel) rather than in Shield's identities table -
 * unlike a single TOTP secret, a user can have several passkeys, which
 * is a genuinely relational, list-shaped thing to store.
 *
 * The actual WebAuthn cryptography (challenge/origin/signature
 * verification) is entirely delegated to web-auth/webauthn-lib via
 * WebauthnFactory - this class's job is orchestration (which
 * ceremony is this, whose credentials, what to store), not
 * cryptography.
 */
class PasskeyIdentityStore
{
    public const ID_TYPE_PASSKEY          = 'passkey';
    public const ID_TYPE_PASSKEY_ACTIVATE = 'passkey_activate';

    private const SESSION_REGISTRATION_OPTIONS  = 'passkey_registration_options';
    private const SESSION_LOGIN_OPTIONS         = 'passkey_login_options';
    private const SESSION_DISCOVERABLE_OPTIONS  = 'passkey_discoverable_login_options';

    protected PasskeyMfaConfig $config;
    protected WebauthnFactory $webauthn;

    /**
     * The specific reason completeAuthentication() last returned
     * false, if any - null after a successful call, or before any
     * call has been made. DIAGNOSTIC addition: plain log_message()
     * alone turned out not to be a reliable way to surface what's
     * actually failing (a real report came back with nothing written
     * to the app's own log at all, despite log_message() calls at
     * every failure branch - most likely an app-specific logging
     * threshold/handler configuration issue, not a code problem, but
     * that's exactly the kind of thing this package can't control or
     * assume). This property gives PasskeyMfa::verify() a way to
     * surface the real reason directly in the page's own flash
     * message instead, which doesn't depend on any logging
     * configuration at all - the same mechanism the view already
     * renders session('error') through, already confirmed working.
     * (The logging itself has since been routed through DiagnosticLog
     * - see that class's own doc comment - so it only ever writes in a
     * development environment; the flash-message fallback above is
     * also gated the same way now, in PasskeyMfa::verify() itself, for
     * the same reason - showing this reason to end users was never
     * meant to be a permanent production behavior.)
     */
    public ?string $lastFailureReason = null;

    public function __construct()
    {
        $this->config   = config('PasskeyMfa');
        $this->webauthn = new WebauthnFactory();
    }

    protected function identities(): UserIdentityModel
    {
        return model(UserIdentityModel::class, false);
    }

    protected function credentials(): PasskeyCredentialModel
    {
        return model(PasskeyCredentialModel::class, false);
    }

    public function hasEnrolled(User $user): bool
    {
        return $this->credentials()->forUser($user->id) !== [];
    }

    /** @return array<int, array<string, mixed>> */
    public function listCredentials(User $user): array
    {
        return $this->credentials()->forUser($user->id);
    }

    public function removeCredential(User $user, int $credentialRowId): void
    {
        $row = $this->credentials()->find($credentialRowId);

        if ($row === null || (int) $row['user_id'] !== $user->id) {
            return;
        }

        $this->credentials()->delete($credentialRowId);
        $this->syncPermanentMarker($user);
    }

    public function renameCredential(User $user, int $credentialRowId, string $name): void
    {
        $row = $this->credentials()->find($credentialRowId);

        if ($row === null || (int) $row['user_id'] !== $user->id) {
            return;
        }

        $this->credentials()->update($credentialRowId, ['name' => $name]);
    }

    // -------------------------------------------------------------------
    // Registration (adding a new passkey)
    // -------------------------------------------------------------------

    /**
     * Ensures Shield's own pending-action check has something to find
     * during a registration ceremony - called from
     * PasskeyActivator::createIdentity(). Does not itself generate any
     * WebAuthn challenge; that happens in beginRegistration(), which is
     * idempotent-safe to call again if this ran first.
     */
    public function ensureActivationMarker(User $user): void
    {
        $existing = $this->identities()
            ->where('user_id', $user->id)
            ->where('type', self::ID_TYPE_PASSKEY_ACTIVATE)
            ->first();

        if ($existing !== null && $existing->expires->getTimestamp() > time()) {
            return;
        }

        if ($existing !== null) {
            $this->identities()->delete($existing->id);
        }

        $this->identities()->create([
            'user_id' => $user->id,
            'type'    => self::ID_TYPE_PASSKEY_ACTIVATE,
            'name'    => null,
            'secret'  => bin2hex(random_bytes(8)), // unused; only its existence matters
            'extra'   => null,
            'expires' => date('Y-m-d H:i:s', time() + $this->config->challengeTtl),
        ]);
    }

    /**
     * Starts a registration ceremony: builds the WebAuthn creation
     * options (excluding any credentials the user already has, so an
     * authenticator that already registered isn't offered again),
     * stashes them in session for completeRegistration() to check
     * against, and returns the JSON to hand to the browser's
     * navigator.credentials.create() call.
     */
    public function beginRegistration(User $user, string $accountName): string
    {
        // REVERTED, CONFIRMED FATAL BUG: an earlier version of this
        // line passed null here, on the mistaken assumption that
        // web-auth/webauthn-lib's own deprecation of
        // PublicKeyCredentialRpEntity's "name" property in v5.3.0 (see
        // webauthn-doc.spomky-labs.com/migration/from-v5.x-to-v6.0)
        // meant the parameter had ALREADY been widened to accept null
        // at the same time. It hadn't - a real app running this
        // package's own declared, supported constraint
        // (composer.json: web-auth/webauthn-lib ^5.1) hit an immediate
        // fatal TypeError: "Argument #1 ($name) must be of type
        // string, null given". Deprecating a feature and changing its
        // type signature are two distinct events that don't
        // necessarily happen together - marking something deprecated
        // typically means "still works, but discouraged," not "already
        // accepts what the FUTURE version will require." Passing the
        // actual string value here is safe across the entire ^5.1
        // range this package declares support for, whether or not any
        // particular installed patch version has started accepting
        // null too - a non-null string satisfies both a `string` and a
        // `?string` parameter type. The [DEPRECATED] log notice this
        // produces on library versions >= 5.3.0 is real but harmless
        // (registration and login both work correctly either way) -
        // living with a harmless warning is the correct trade-off here,
        // not a fatal error in exchange for silencing it. If this
        // package's own composer.json constraint is ever raised to
        // require web-auth/webauthn-lib ^5.3 specifically (guaranteeing
        // the null-accepting behavior is present), revisit this line -
        // and if it's ever raised to allow ^6.0, this call needs
        // updating regardless, since v6.0 removes the parameter
        // entirely rather than just deprecating it.
        $rpEntity   = PublicKeyCredentialRpEntity::create($this->config->rpName, $this->config->rpId);
        $userHandle = (string) $user->id;
        $userEntity = PublicKeyCredentialUserEntity::create($accountName, $userHandle, $accountName);

        $excludeCredentials = array_map(
            static fn (array $row): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create(
                'public-key',
                Base64Url::decode($row['credential_id'])
            ),
            $this->listCredentials($user)
        );

        $challenge = random_bytes(32);

        // Confirmed via web-auth/webauthn-lib's own official docs
        // (webauthn-doc.spomky-labs.com/pure-php/advanced-behaviours/authenticator-selection-criteria) -
        // residentKey accepts the raw WebAuthn spec string values
        // directly ('discouraged'/'preferred'/'required'), not a
        // dedicated enum type, so Config\PasskeyMfa::$residentKeyRequirement
        // is passed straight through rather than mapped through
        // library-specific constants this class would otherwise need
        // to import. See that config property's own doc comment for
        // what this controls and why 'preferred' - the library's own
        // default when this whole parameter is omitted, which is what
        // earlier versions of this method did - is the default here
        // too, just stated explicitly.
        $authenticatorSelection = AuthenticatorSelectionCriteria::create(
            residentKey: $this->config->residentKeyRequirement,
        );

        $options = PublicKeyCredentialCreationOptions::create(
            $rpEntity,
            $userEntity,
            $challenge,
            authenticatorSelection: $authenticatorSelection,
            excludeCredentials: $excludeCredentials,
        );

        $json = $this->webauthn->serializer()->serialize($options, 'json');
        session()->set(self::SESSION_REGISTRATION_OPTIONS, $json);

        return $json;
    }

    /**
     * Verifies the browser's registration response against the
     * options stashed by beginRegistration(), and on success stores
     * the new credential and ensures the permanent 'passkey' marker
     * exists. Returns false (never throws) on any failure - a wrong,
     * expired, or tampered response is a normal, expected outcome to
     * handle gracefully, not an exceptional one.
     */
    public function completeRegistration(User $user, string $responseJson, ?string $label = null): bool
    {
        $optionsJson = session(self::SESSION_REGISTRATION_OPTIONS);

        if ($optionsJson === null) {
            return false;
        }

        try {
            /** @var PublicKeyCredentialCreationOptions $options */
            $options = $this->webauthn->serializer()->deserialize(
                $optionsJson,
                PublicKeyCredentialCreationOptions::class,
                'json'
            );

            /** @var PublicKeyCredential $publicKeyCredential */
            $publicKeyCredential = $this->webauthn->serializer()->deserialize(
                $responseJson,
                PublicKeyCredential::class,
                'json'
            );

            if (! $publicKeyCredential->response instanceof AuthenticatorAttestationResponse) {
                return false;
            }

            $credentialSource = $this->webauthn->attestationValidator()->check(
                $publicKeyCredential->response,
                $options,
                $this->config->rpId,
            );
        } catch (\Throwable) {
            // Any failure here - a wrong challenge, a tampered
            // response, an origin mismatch - is a normal "registration
            // didn't succeed" outcome, not something to let bubble up
            // as an unhandled exception.
            return false;
        }

        $this->credentials()->insert([
            'user_id'                      => $user->id,
            'credential_id'                => Base64Url::encode($credentialSource->publicKeyCredentialId),
            'public_key_credential_source' => $this->webauthn->serializer()->serialize($credentialSource, 'json'),
            'name'                         => $label !== null && $label !== '' ? $label : null,
            'last_used_at'                 => null,
        ]);

        $this->syncPermanentMarker($user);
        session()->remove(self::SESSION_REGISTRATION_OPTIONS);

        return true;
    }

    public function cancelRegistration(): void
    {
        session()->remove(self::SESSION_REGISTRATION_OPTIONS);
    }

    // -------------------------------------------------------------------
    // Authentication (login-time verification)
    // -------------------------------------------------------------------

    /**
     * Starts a login ceremony: builds the WebAuthn request options
     * (listing the user's own registered credentials as the allowed
     * set), stashes them in session, and returns the JSON to hand to
     * the browser's navigator.credentials.get() call.
     */
    public function beginAuthentication(User $user): string
    {
        $allowCredentials = array_map(
            static fn (array $row): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create(
                'public-key',
                Base64Url::decode($row['credential_id'])
            ),
            $this->listCredentials($user)
        );

        $challenge = random_bytes(32);

        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            rpId: $this->config->rpId,
            allowCredentials: $allowCredentials,
        );

        $json = $this->webauthn->serializer()->serialize($options, 'json');
        session()->set(self::SESSION_LOGIN_OPTIONS, $json);

        return $json;
    }

    /**
     * Verifies the browser's login response against the options
     * stashed by beginAuthentication() and the specific credential's
     * previously-stored public key. Returns false (never throws) on
     * any failure - see completeRegistration()'s doc comment for why.
     *
     * TEMPORARY DIAGNOSTIC LOGGING added at every failure point below -
     * a real, confirmed gap where every failure silently returned
     * false with zero visibility into why, which made a real reported
     * bug (login failing specifically once a user has multiple
     * registered passkeys) impossible to diagnose from the outside.
     * Safe to leave in permanently - only ever writes when something
     * has already gone wrong, adding no overhead to the success path,
     * and (via DiagnosticLog) only ever writes in a development
     * environment in the first place - see that class's own doc
     * comment for why.
     */
    public function completeAuthentication(User $user, string $responseJson): bool
    {
        $this->lastFailureReason = null;

        $optionsJson = session(self::SESSION_LOGIN_OPTIONS);

        if ($optionsJson === null) {
            $this->lastFailureReason = 'no pending options in session';
            DiagnosticLog::write('error', 'PasskeyMfa completeAuthentication: no pending options in session for user_id {user_id}.', ['user_id' => $user->id]);

            return false;
        }

        try {
            /** @var PublicKeyCredentialRequestOptions $options */
            $options = $this->webauthn->serializer()->deserialize(
                $optionsJson,
                PublicKeyCredentialRequestOptions::class,
                'json'
            );

            /** @var PublicKeyCredential $publicKeyCredential */
            $publicKeyCredential = $this->webauthn->serializer()->deserialize(
                $responseJson,
                PublicKeyCredential::class,
                'json'
            );

            if (! $publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
                $this->lastFailureReason = 'deserialized response was not an AuthenticatorAssertionResponse';
                DiagnosticLog::write('error', 'PasskeyMfa completeAuthentication: deserialized response was not an AuthenticatorAssertionResponse for user_id {user_id}.', ['user_id' => $user->id]);

                return false;
            }

            $credentialIdB64 = Base64Url::encode($publicKeyCredential->rawId);
            $row             = $this->credentials()->findByCredentialId($credentialIdB64);

            if ($row === null) {
                $this->lastFailureReason = "no stored credential row found for credential_id {$credentialIdB64}";
                DiagnosticLog::write('error', 'PasskeyMfa completeAuthentication: no stored credential row found for credential_id {credential_id} (user_id {user_id}).', ['credential_id' => $credentialIdB64, 'user_id' => $user->id]);

                return false;
            }

            if ((int) $row['user_id'] !== $user->id) {
                $this->lastFailureReason = "credential_id {$credentialIdB64} belongs to a different user_id ({$row['user_id']}) than the expected {$user->id}";
                DiagnosticLog::write('error', 'PasskeyMfa completeAuthentication: credential_id {credential_id} belongs to user_id {row_user_id}, not the expected user_id {user_id}.', ['credential_id' => $credentialIdB64, 'row_user_id' => $row['user_id'], 'user_id' => $user->id]);

                return false;
            }

            /** @var PublicKeyCredentialSource $storedSource */
            $storedSource = $this->webauthn->serializer()->deserialize(
                $row['public_key_credential_source'],
                PublicKeyCredentialSource::class,
                'json'
            );

            // NOTE: check()'s exact parameter list is the single most
            // likely spot in this file to need adjusting for your
            // installed library version - see WebauthnFactory's class
            // doc comment. It returns an updated PublicKeyCredentialSource
            // (with the incremented signature counter) on success.
            $updatedSource = $this->webauthn->assertionValidator()->check(
                $storedSource,
                $publicKeyCredential->response,
                $options,
                $this->config->rpId,
                (string) $user->id,
            );
        } catch (\Throwable $e) {
            $this->lastFailureReason = get_class($e) . ': ' . $e->getMessage();
            DiagnosticLog::write('error', 'PasskeyMfa completeAuthentication: {exception}', ['exception' => $e]);

            return false;
        }

        $this->credentials()->update($row['id'], [
            'public_key_credential_source' => $this->webauthn->serializer()->serialize($updatedSource, 'json'),
            'last_used_at'                 => date('Y-m-d H:i:s'),
        ]);

        session()->remove(self::SESSION_LOGIN_OPTIONS);

        return true;
    }

    /**
     * Starts a "login with a passkey" ceremony with NO known user at
     * all - the discoverable/usernameless counterpart to
     * beginAuthentication() above. Deliberately omits allowCredentials
     * entirely rather than passing an empty array - confirmed via
     * web-auth/webauthn-lib's own official documentation
     * (webauthn-doc.spomky-labs.com/pure-php/advanced-behaviours/authentication-without-username)
     * as the correct way to request this; the browser's own passkey
     * picker shows whichever credentials it has for this site's rpId,
     * across every account, not just one the server already has in
     * mind.
     *
     * Requires the credential being used to have been registered as
     * discoverable ("resident key") in the first place - see
     * Config\PasskeyMfa::$residentKeyRequirement's own doc comment for
     * what this package requests at registration time, and its
     * important caveat about credentials registered before that
     * setting existed.
     */
    public function beginDiscoverableAuthentication(): string
    {
        $challenge = random_bytes(32);

        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            rpId: $this->config->rpId,
        );

        $json = $this->webauthn->serializer()->serialize($options, 'json');
        session()->set(self::SESSION_DISCOVERABLE_OPTIONS, $json);

        return $json;
    }

    /**
     * Verifies a discoverable/usernameless login response and, on
     * success, returns WHICHEVER user it turned out to be - unlike
     * completeAuthentication() above, the caller doesn't know this in
     * advance, since that's the entire point of this method existing
     * separately.
     *
     * SECURITY DESIGN, worth being explicit about: the user is derived
     * from the SAME trusted, server-side credential_id -> user_id
     * lookup completeAuthentication() already relies on
     * (PasskeyCredentialModel::findByCredentialId(), populated only at
     * registration time under this app's own control) - NOT from the
     * assertion response's own userHandle field, even though that
     * field is available and is what many WebAuthn tutorials read
     * directly for exactly this purpose. Trusting a client-supplied
     * field to determine identity, ahead of any cryptographic check,
     * is a weaker design than deriving the same answer from data this
     * server already controls and only afterward confirming the
     * cryptographic signature actually matches that specific stored
     * credential - assertionValidator()->check() below is what
     * actually proves the visitor holds the matching private key; the
     * lookup above is only ever a CANDIDATE identity until that check
     * passes. If it fails, this returns null - the candidate user is
     * never trusted or returned regardless of how the lookup went.
     *
     * Returns null (never throws) on any failure, mirroring
     * completeAuthentication()'s own "never throw" contract - see that
     * method's own doc comment, and completeRegistration()'s, for why.
     */
    public function completeDiscoverableAuthentication(string $responseJson): ?User
    {
        $this->lastFailureReason = null;

        $optionsJson = session(self::SESSION_DISCOVERABLE_OPTIONS);

        if ($optionsJson === null) {
            $this->lastFailureReason = 'no pending discoverable options in session';
            DiagnosticLog::write('error', 'PasskeyMfa completeDiscoverableAuthentication: no pending options in session.');

            return null;
        }

        try {
            /** @var PublicKeyCredentialRequestOptions $options */
            $options = $this->webauthn->serializer()->deserialize(
                $optionsJson,
                PublicKeyCredentialRequestOptions::class,
                'json'
            );

            /** @var PublicKeyCredential $publicKeyCredential */
            $publicKeyCredential = $this->webauthn->serializer()->deserialize(
                $responseJson,
                PublicKeyCredential::class,
                'json'
            );

            if (! $publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
                $this->lastFailureReason = 'deserialized response was not an AuthenticatorAssertionResponse';
                DiagnosticLog::write('error', 'PasskeyMfa completeDiscoverableAuthentication: deserialized response was not an AuthenticatorAssertionResponse.');

                return null;
            }

            $credentialIdB64 = Base64Url::encode($publicKeyCredential->rawId);
            $row             = $this->credentials()->findByCredentialId($credentialIdB64);

            if ($row === null) {
                $this->lastFailureReason = "no stored credential row found for credential_id {$credentialIdB64}";
                DiagnosticLog::write('error', 'PasskeyMfa completeDiscoverableAuthentication: no stored credential row found for credential_id {credential_id}.', ['credential_id' => $credentialIdB64]);

                return null;
            }

            // The CANDIDATE user, from this server's own trusted data -
            // not yet proven to be who actually made this request. See
            // this method's own doc comment for why this ordering (and
            // not reading userHandle directly) is the safer design.
            $candidateUser = model(UserModel::class)->find((int) $row['user_id']);

            if ($candidateUser === null) {
                $this->lastFailureReason = "credential_id {$credentialIdB64} references a user_id ({$row['user_id']}) that no longer exists";
                DiagnosticLog::write('error', 'PasskeyMfa completeDiscoverableAuthentication: credential_id {credential_id} references a user_id that no longer exists.', ['credential_id' => $credentialIdB64]);

                return null;
            }

            /** @var PublicKeyCredentialSource $storedSource */
            $storedSource = $this->webauthn->serializer()->deserialize(
                $row['public_key_credential_source'],
                PublicKeyCredentialSource::class,
                'json'
            );

            // Identical validation call to completeAuthentication()'s
            // own - same NOTE about check()'s own version sensitivity
            // applies here too. The only difference is that
            // (string) $candidateUser->id was DERIVED above, rather
            // than being an input the caller already knew.
            $updatedSource = $this->webauthn->assertionValidator()->check(
                $storedSource,
                $publicKeyCredential->response,
                $options,
                $this->config->rpId,
                (string) $candidateUser->id,
            );
        } catch (\Throwable $e) {
            $this->lastFailureReason = get_class($e) . ': ' . $e->getMessage();
            DiagnosticLog::write('error', 'PasskeyMfa completeDiscoverableAuthentication: {exception}', ['exception' => $e]);

            return null;
        }

        $this->credentials()->update($row['id'], [
            'public_key_credential_source' => $this->webauthn->serializer()->serialize($updatedSource, 'json'),
            'last_used_at'                 => date('Y-m-d H:i:s'),
        ]);

        session()->remove(self::SESSION_DISCOVERABLE_OPTIONS);

        // Only NOW, after the cryptographic check above has actually
        // succeeded, is the candidate user trusted and returned.
        return $candidateUser;
    }

    public function cancelAuthentication(): void
    {
        session()->remove(self::SESSION_LOGIN_OPTIONS);
    }

    // -------------------------------------------------------------------

    /**
     * Keeps the permanent 'passkey' marker in sync with whether any
     * real credential rows actually exist - created the moment the
     * first one is added, removed the moment the last one is removed,
     * so Shield's own pending-check (which only cares whether an
     * identity of getType() exists, not its content) always correctly
     * reflects "has this user got a passkey at all".
     *
     * CONFIRMED, REAL BUG FIXED HERE, and the most severe one found
     * across this whole series: an earlier version stored a fixed
     * literal string ('n/a') as the secret, on the reasoning that "it's
     * never read, only the marker's existence matters." That reasoning
     * missed Shield's own auth_identities UNIQUE(type, secret)
     * constraint - NOT (user_id, type, secret) - so ANY TWO users who
     * both had at least one passkey credential would both produce
     * (type='passkey', secret='n/a'), an identical pair. Unlike the
     * WhatsApp bugs this same reasoning also affected (see
     * shield-whatsapp-mfa's PhoneNumberStore), this one needed no
     * coincidence and no timing window at all - it's PERMANENT, so the
     * second person to EVER enroll a passkey in a real, multi-user app
     * would hit a duplicate-key database error and be unable to
     * complete registration, indefinitely, not just during a brief
     * window. Randomizing the value (matching this same class's own
     * ensureActivationMarker(), a few methods up, which already did
     * this correctly) removes the collision entirely - the marker's
     * existence is still all that's ever checked, its content remains
     * genuinely unused.
     */
    protected function syncPermanentMarker(User $user): void
    {
        $hasCredentials = $this->hasEnrolled($user);
        $existingMarker = $this->identities()
            ->where('user_id', $user->id)
            ->where('type', self::ID_TYPE_PASSKEY)
            ->first();

        if ($hasCredentials && $existingMarker === null) {
            $this->identities()->create([
                'user_id' => $user->id,
                'type'    => self::ID_TYPE_PASSKEY,
                'name'    => null,
                'secret'  => bin2hex(random_bytes(8)), // unused; only its existence matters - randomized so no two users' rows can collide
                'extra'   => null,
                'expires' => null, // permanent
            ]);
        } elseif (! $hasCredentials && $existingMarker !== null) {
            $this->identities()->delete($existingMarker->id);
        }
    }
}
