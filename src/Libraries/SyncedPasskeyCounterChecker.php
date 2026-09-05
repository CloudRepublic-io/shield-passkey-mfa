<?php

declare(strict_types=1);

namespace PasskeyMfa\Libraries;

use RuntimeException;
use Webauthn\Counter\CounterChecker;
use Webauthn\CredentialRecord;

/**
 * Implements the W3C WebAuthn Level 2 guidance on signature counters
 * correctly for synced/platform passkeys - web-auth/webauthn-lib's own
 * default counter checker (Webauthn\Counter\ThrowExceptionIfInvalid)
 * does not.
 *
 * CONFIRMED, REAL BUG THIS FIXES: synced passkeys (iCloud Keychain,
 * Google Password Manager, and Windows Hello's own cloud sync -
 * exactly what Chrome, Edge, and Safari's built-in passkey managers
 * use) report a signature counter of 0 on every single authentication,
 * permanently. This is explicit, spec-compliant, intentional behavior,
 * not a bug in those platforms - the W3C WebAuthn spec itself says: if
 * both the stored and returned counters are 0, the authenticator does
 * not support the counter, and the check should be skipped entirely. A
 * strictly-increasing counter has no coherent meaning for a credential
 * that can legitimately be used from several independently-synced
 * devices at once, which is the whole point of a synced passkey.
 *
 * The library's default checker hard-rejects this: stored=0, new=0, 0
 * is not greater than 0, so verification fails - meaning EVERY login
 * attempt with a synced passkey fails, unconditionally, regardless of
 * how many credentials a user has registered or which device they're
 * on. This is not a rare edge case affecting unusual setups - it's the
 * default, expected behavior of the passkeys most real users actually
 * have, so this fix is wired in unconditionally in WebauthnFactory, not
 * offered as an opt-in config toggle.
 *
 * A genuinely non-zero counter (hardware security keys - YubiKeys and
 * similar - typically do implement a real, incrementing one) is still
 * checked properly: it must be strictly greater than what's stored, or
 * this throws - preserving the counter's original, legitimate purpose
 * (detecting a cloned hardware authenticator) for the credentials
 * where that check actually means something.
 *
 * VERSION SENSITIVITY - CONFIRMED, REAL FIX applied here after an
 * earlier version of this file caused a real fatal error against a
 * real app: "Declaration ... must be compatible with
 * Webauthn\Counter\CounterChecker::check(Webauthn\CredentialRecord
 * $credentialRecord, int $currentCounter): void". That earlier version
 * type-hinted Webauthn\PublicKeyCredentialSource and called
 * ->getCounter() - confirmed WRONG on both counts against
 * web-auth/webauthn-lib's own official current documentation
 * (webauthn-doc.spomky-labs.com/prerequisites/credential-record):
 *
 *   "Renamed in v5.3.0: The class Webauthn\PublicKeyCredentialSource
 *   has been renamed to Webauthn\CredentialRecord. The old class name
 *   is deprecated and will be removed in version 6.0.
 *   PublicKeyCredentialSource now extends CredentialRecord for
 *   backward compatibility."
 *
 * - and that same documentation's own example reads the counter as a
 * direct property (`$credentialRecord->counter`), not a method call.
 * Both are fixed here: the type hint now matches the actual interface
 * (CredentialRecord, not the now-deprecated PublicKeyCredentialSource
 * subclass of it), and the counter is read via ->counter directly.
 * Since PublicKeyCredentialSource extends CredentialRecord, a
 * PublicKeyCredentialSource instance (which is what
 * PasskeyIdentityStore::completeAuthentication() actually passes
 * through the library's own internals) still satisfies this type hint
 * and still exposes the same ->counter property, inherited from its
 * parent - no other file in this package needed to change.
 */
class SyncedPasskeyCounterChecker implements CounterChecker
{
    public function check(CredentialRecord $credentialRecord, int $currentCounter): void
    {
        $storedCounter = $credentialRecord->counter;

        if ($storedCounter === 0 && $currentCounter === 0) {
            return;
        }

        if ($currentCounter <= $storedCounter) {
            throw new RuntimeException('Signature counter did not increase - possible cloned credential.');
        }
    }
}
