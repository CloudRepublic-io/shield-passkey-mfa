<?php

declare(strict_types=1);

namespace PasskeyMfa\Libraries;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

/**
 * Builds the web-auth/webauthn-lib services this package needs, in one
 * place. THIS IS THE MOST VERSION-SENSITIVE FILE IN THIS PACKAGE.
 *
 * web-auth/webauthn-lib has changed its core setup API significantly
 * across major versions - v3.x used PSR-7 requests and a
 * PublicKeyCredentialLoader class; v4.8 deprecated that in favor of a
 * Symfony Serializer-based approach; v5.0 removed the deprecated
 * classes entirely and introduced Webauthn\CeremonyStep\CeremonyStepManagerFactory
 * as the way validators get their actual verification logic (challenge
 * matching, origin checking, signature counter checks, etc.) - the
 * code below was written against that v5.x shape, confirmed via the
 * library's own current documentation
 * (https://webauthn-doc.spomky-labs.com/pure-php/input-validation and
 * .../pure-php/authenticator-registration) rather than assumed from
 * memory. Given how much this API has moved in the past, if you're on
 * a noticeably different installed version:
 *
 *   1. Check `composer show web-auth/webauthn-lib` for your exact
 *      installed version.
 *   2. Compare every method call in this file against
 *      vendor/web-auth/webauthn-lib's own README/CHANGELOG for that
 *      version - a signature mismatch here fails loudly (a PHP
 *      TypeError), not silently, so this is safe to iterate on rather
 *      than a hidden security gap.
 *   3. Before relying on this in production, run a real registration
 *      and a real login through an actual browser and authenticator at
 *      least once - this is the one package in this whole series where
 *      "the code looks right" is meaningfully less reassuring than
 *      usual, given how cryptography-heavy the actual verification is.
 *
 * Only "none" attestation is supported (see attestationStatementSupportManager()
 * below) - the library's own recommended default unless you have a
 * specific need to verify authenticator make/model, which adds real
 * complexity (a Metadata Statement Repository, certificate chain
 * validation) this package doesn't attempt.
 *
 * assertionValidator() wires in SyncedPasskeyCounterChecker (see that
 * class's own doc comment) rather than the library's own default
 * counter checker - CONFIRMED, REAL BUG this fixes: the library's
 * default hard-rejects every login from a synced passkey (Chrome,
 * Edge, and Safari's own built-in, cloud-synced passkey managers -
 * most real users' actual setup), unconditionally, since those report
 * a signature counter of 0 forever, which the default checker treats
 * as invalid rather than as the W3C's own documented "this
 * authenticator doesn't support a counter" case.
 */
class WebauthnFactory
{
    private ?SerializerInterface $serializer = null;
    private ?AuthenticatorAttestationResponseValidator $attestationValidator = null;
    private ?AuthenticatorAssertionResponseValidator $assertionValidator     = null;

    /**
     * Used to (de)serialize PublicKeyCredentialCreationOptions,
     * PublicKeyCredentialRequestOptions, PublicKeyCredential, and
     * PublicKeyCredentialSource objects to/from JSON - both for
     * talking to the browser and for our own session/database storage.
     */
    public function serializer(): SerializerInterface
    {
        if ($this->serializer === null) {
            $attestationStatementSupportManager = AttestationStatementSupportManager::create();
            $attestationStatementSupportManager->add(NoneAttestationStatementSupport::create());

            $factory          = new WebauthnSerializerFactory($attestationStatementSupportManager);
            $this->serializer = $factory->create();
        }

        return $this->serializer;
    }

    /** Used when verifying a registration (creation) ceremony response. */
    public function attestationValidator(): AuthenticatorAttestationResponseValidator
    {
        if ($this->attestationValidator === null) {
            $csmFactory = new CeremonyStepManagerFactory();

            $this->attestationValidator = AuthenticatorAttestationResponseValidator::create(
                ceremonyStepManager: $csmFactory->creationCeremony()
            );
        }

        return $this->attestationValidator;
    }

    /** Used when verifying a login (request/assertion) ceremony response. */
    public function assertionValidator(): AuthenticatorAssertionResponseValidator
    {
        if ($this->assertionValidator === null) {
            $csmFactory = new CeremonyStepManagerFactory();

            // CONFIRMED, REAL FIX - see SyncedPasskeyCounterChecker's
            // own class doc comment for the full explanation: without
            // this, the library's own default counter checker rejects
            // every login attempt from a synced passkey (Chrome/Edge/Safari's
            // own built-in, cloud-synced passkey managers - i.e. most
            // real users' actual setup), unconditionally. Must be set
            // BEFORE requestCeremony() is called below - that's what
            // actually builds the validation pipeline using it.
            $csmFactory->setCounterChecker(new SyncedPasskeyCounterChecker());

            $this->assertionValidator = AuthenticatorAssertionResponseValidator::create(
                ceremonyStepManager: $csmFactory->requestCeremony()
            );
        }

        return $this->assertionValidator;
    }
}
