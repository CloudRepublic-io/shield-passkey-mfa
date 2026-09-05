<?php

declare(strict_types=1);

namespace Tests\PasskeyMfa\Libraries;

use CodeIgniter\Test\CIUnitTestCase;
use PasskeyMfa\Libraries\SyncedPasskeyCounterChecker;
use ReflectionObject;
use RuntimeException;
use Webauthn\CredentialRecord;

/**
 * Tests SyncedPasskeyCounterChecker's own comparison logic in
 * isolation - pure, deterministic logic with no cryptography or
 * WebAuthn ceremony involved at all, unlike most of this package's own
 * tests (see PasskeyIdentityStoreTest's class doc comment for why
 * THOSE can't cover the real crypto success path) - this one genuinely
 * can be, and is, fully covered.
 *
 * Uses a PHPUnit mock for CredentialRecord, with its own "counter"
 * property set directly via reflection rather than through the mock's
 * own constructor - CredentialRecord's real constructor needs several
 * WebAuthn-specific arguments (credential ID, public key, transports,
 * etc.) irrelevant to what's under test here, and reflection sidesteps
 * needing to get all of those right just to test a single property
 * comparison. This also avoids assuming the property is publicly
 * writable (it may be declared readonly) - reflection's setAccessible()
 * bypasses that regardless, the same pattern already established
 * elsewhere in this series for exactly this kind of situation.
 */
final class SyncedPasskeyCounterCheckerTest extends CIUnitTestCase
{
    private function credentialRecordWithCounter(int $counter): CredentialRecord
    {
        $record = $this->createMock(CredentialRecord::class);

        $reflection = new ReflectionObject($record);
        $property   = $reflection->getProperty('counter');
        $property->setAccessible(true);
        $property->setValue($record, $counter);

        return $record;
    }

    /**
     * THE regression test for the actual bug - see
     * SyncedPasskeyCounterChecker's own class doc comment for the full
     * explanation. This exact shape (stored=0, new=0) is what every
     * synced passkey (Chrome/Edge/Safari's own built-in passkey
     * managers) produces on every single login, permanently.
     */
    public function testBothCountersZeroIsTreatedAsAnAuthenticatorThatDoesNotSupportCounters(): void
    {
        $checker = new SyncedPasskeyCounterChecker();

        $checker->check($this->credentialRecordWithCounter(0), 0);
        $this->addToAssertionCount(1); // did not throw
    }

    public function testIncreasingCounterIsAccepted(): void
    {
        $checker = new SyncedPasskeyCounterChecker();

        $checker->check($this->credentialRecordWithCounter(5), 6);
        $this->addToAssertionCount(1); // did not throw
    }

    public function testNonIncreasingNonZeroCounterIsRejected(): void
    {
        $checker = new SyncedPasskeyCounterChecker();

        $this->expectException(RuntimeException::class);
        $checker->check($this->credentialRecordWithCounter(5), 5);
    }

    public function testDecreasingCounterIsRejected(): void
    {
        $checker = new SyncedPasskeyCounterChecker();

        $this->expectException(RuntimeException::class);
        $checker->check($this->credentialRecordWithCounter(10), 3);
    }

    /**
     * A stored, non-zero counter (e.g. a hardware key that WAS
     * incrementing normally) followed by a returned 0 is NOT the same
     * "this authenticator doesn't support counters" case - both must
     * be zero for that exception to apply. A previously-incrementing
     * counter suddenly reporting 0 is exactly the kind of signal a
     * strict check should still catch, not silently wave through.
     */
    public function testOnlyBothZeroQualifiesForTheException(): void
    {
        $checker = new SyncedPasskeyCounterChecker();

        $this->expectException(RuntimeException::class);
        $checker->check($this->credentialRecordWithCounter(5), 0);
    }
}
