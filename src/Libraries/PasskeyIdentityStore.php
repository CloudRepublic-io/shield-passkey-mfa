<?php

declare(strict_types=1);

namespace PasskeyMfa\Libraries;

use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserIdentityModel;
use Config\PasskeyMfa as PasskeyMfaConfig;
use PasskeyMfa\Models\PasskeyCredentialModel;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
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

    private const SESSION_REGISTRATION_OPTIONS = 'passkey_registration_options';
    private const SESSION_LOGIN_OPTIONS        = 'passkey_login_options';

    protected PasskeyMfaConfig $config;
    protected WebauthnFactory $webauthn;

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

        $options = PublicKeyCredentialCreationOptions::create(
            $rpEntity,
            $userEntity,
            $challenge,
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
     * Safe to leave in permanently - log_message('error', ...) only
     * writes when something has already gone wrong, so this adds no
     * overhead to the success path.
     */
    public function completeAuthentication(User $user, string $responseJson): bool
    {
        $optionsJson = session(self::SESSION_LOGIN_OPTIONS);

        if ($optionsJson === null) {
            log_message('error', 'PasskeyMfa completeAuthentication: no pending options in session for user_id {user_id}.', ['user_id' => $user->id]);

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
                log_message('error', 'PasskeyMfa completeAuthentication: deserialized response was not an AuthenticatorAssertionResponse for user_id {user_id}.', ['user_id' => $user->id]);

                return false;
            }

            $credentialIdB64 = Base64Url::encode($publicKeyCredential->rawId);
            $row             = $this->credentials()->findByCredentialId($credentialIdB64);

            if ($row === null) {
                log_message('error', 'PasskeyMfa completeAuthentication: no stored credential row found for credential_id {credential_id} (user_id {user_id}).', ['credential_id' => $credentialIdB64, 'user_id' => $user->id]);

                return false;
            }

            if ((int) $row['user_id'] !== $user->id) {
                log_message('error', 'PasskeyMfa completeAuthentication: credential_id {credential_id} belongs to user_id {row_user_id}, not the expected user_id {user_id}.', ['credential_id' => $credentialIdB64, 'row_user_id' => $row['user_id'], 'user_id' => $user->id]);

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
            log_message('error', 'PasskeyMfa completeAuthentication: {exception}', ['exception' => $e]);

            return false;
        }

        $this->credentials()->update($row['id'], [
            'public_key_credential_source' => $this->webauthn->serializer()->serialize($updatedSource, 'json'),
            'last_used_at'                 => date('Y-m-d H:i:s'),
        ]);

        session()->remove(self::SESSION_LOGIN_OPTIONS);

        return true;
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
