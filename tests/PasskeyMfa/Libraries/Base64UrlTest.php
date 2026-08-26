<?php

declare(strict_types=1);

namespace Tests\PasskeyMfa\Libraries;

use CodeIgniter\Test\CIUnitTestCase;
use PasskeyMfa\Libraries\Base64Url;

/**
 * Pure round-trip/format tests - no database or HTTP involved, no
 * dependency on web-auth/webauthn-lib either, since this codec is
 * deliberately self-contained.
 */
final class Base64UrlTest extends CIUnitTestCase
{
    public function testEncodeDecodeRoundTrip(): void
    {
        $original = random_bytes(32);

        $this->assertSame($original, Base64Url::decode(Base64Url::encode($original)));
    }

    public function testEncodeProducesNoPaddingOrUnsafeCharacters(): void
    {
        // Deliberately includes bytes that would produce '+', '/', and
        // '=' padding under plain base64, to actually exercise the
        // url-safe substitution and padding removal.
        $encoded = Base64Url::encode(str_repeat("\xFF\xFE\xFD", 10));

        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
        $this->assertStringNotContainsString('=', $encoded);
    }

    public function testDecodeHandlesEveryPaddingLengthCorrectly(): void
    {
        // Base64 padding needs vary by input length mod 3 - covering
        // several lengths catches an off-by-one in the padding
        // calculation that a single test length could miss.
        foreach ([1, 2, 3, 4, 5, 10, 16, 32] as $length) {
            $original = random_bytes($length);

            $this->assertSame(
                $original,
                Base64Url::decode(Base64Url::encode($original)),
                "Round trip failed for a {$length}-byte input"
            );
        }
    }

    public function testEmptyStringRoundTrips(): void
    {
        $this->assertSame('', Base64Url::encode(''));
        $this->assertSame('', Base64Url::decode(''));
    }
}
