<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * Canonical JSON and SHA-256 helpers. The audit hash chain, approval ids,
 * bundle versions and bundle signatures depend on this being byte-identical
 * in every port: keys sorted by Unicode code point, no white space, non-ASCII
 * characters written as themselves, control characters as \u00xx (lowercase).
 * Written by hand; json_encode() is not used.
 */
final class Canon
{
    public static function canon(mixed $value): string
    {
        return Json::encode($value, false, true, ',', ':');
    }

    public static function sha256Hex(string $bytes): string
    {
        return hash('sha256', $bytes);
    }

    public static function hashValue(mixed $value): string
    {
        return hash('sha256', self::canon($value));
    }
}
