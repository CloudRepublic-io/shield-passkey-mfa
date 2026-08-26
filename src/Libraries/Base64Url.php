<?php

declare(strict_types=1);

namespace PasskeyMfa\Libraries;

/**
 * RFC 4648 base64url, used only for storing/looking up credential IDs
 * in our own database - deliberately self-contained rather than
 * relying on whatever web-auth/webauthn-lib does internally for its
 * own (de)serialization, so this part carries no version-sensitivity.
 */
final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode(string $data): string
    {
        $padded = str_pad($data, strlen($data) + (4 - strlen($data) % 4) % 4, '=');

        return base64_decode(strtr($padded, '-_', '+/'), true) ?: '';
    }
}
