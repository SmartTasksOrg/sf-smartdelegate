<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * Exact integer arithmetic on int|BigInt. PHP integer overflow silently
 * becomes a float, so every sum the engine makes with caller-supplied numbers
 * goes through here.
 */
final class Num
{
    /** A JSON integer (not a bool, not a float). */
    public static function isInt(mixed $v): bool
    {
        return is_int($v) || $v instanceof BigInt;
    }

    /** `-?digits` -> int when it fits in 64 bits, else BigInt. */
    public static function parse(string $s): int|BigInt
    {
        $neg = $s !== '' && $s[0] === '-';
        $d = ltrim($neg ? substr($s, 1) : $s, '0');
        if ($d === '') {
            return 0;
        }
        if (strlen($d) < 19) {
            return $neg ? -(int) $d : (int) $d;
        }
        if (strlen($d) === 19) {
            if ($neg && strcmp($d, '9223372036854775808') <= 0) {
                return $d === '9223372036854775808' ? PHP_INT_MIN : -(int) $d;
            }
            if (!$neg && strcmp($d, '9223372036854775807') <= 0) {
                return (int) $d;
            }
        }
        return new BigInt(($neg ? '-' : '') . $d);
    }

    public static function str(int|BigInt $v): string
    {
        return is_int($v) ? (string) $v : $v->digits;
    }

    /** -1, 0, 1 */
    public static function cmp(int|BigInt $a, int|BigInt $b): int
    {
        if (is_int($a) && is_int($b)) {
            return $a <=> $b;
        }
        [$an, $am] = self::split(self::str($a));
        [$bn, $bm] = self::split(self::str($b));
        if ($an !== $bn) {
            return $an ? -1 : 1;
        }
        $c = self::cmpMag($am, $bm);
        return $an ? -$c : $c;
    }

    public static function add(int|BigInt $a, int|BigInt $b): int|BigInt
    {
        if (is_int($a) && is_int($b)) {
            $r = $a + $b;
            if (is_int($r)) {
                return $r;
            }
        }
        [$an, $am] = self::split(self::str($a));
        [$bn, $bm] = self::split(self::str($b));
        if ($an === $bn) {
            return self::parse(($an ? '-' : '') . self::addMag($am, $bm));
        }
        $c = self::cmpMag($am, $bm);
        if ($c === 0) {
            return 0;
        }
        return $c > 0
            ? self::parse(($an ? '-' : '') . self::subMag($am, $bm))
            : self::parse(($bn ? '-' : '') . self::subMag($bm, $am));
    }

    public static function neg(int|BigInt $a): int|BigInt
    {
        $s = self::str($a);
        return self::parse($s[0] === '-' ? substr($s, 1) : '-' . $s);
    }

    public static function sub(int|BigInt $a, int|BigInt $b): int|BigInt
    {
        if (is_int($a) && is_int($b)) {
            $r = $a - $b;
            if (is_int($r)) {
                return $r;
            }
        }
        return self::add($a, self::neg($b));
    }

    public static function min(int|BigInt $a, int|BigInt $b): int|BigInt
    {
        return self::cmp($b, $a) < 0 ? $b : $a;
    }

    public static function max(int|BigInt $a, int|BigInt $b): int|BigInt
    {
        return self::cmp($b, $a) > 0 ? $b : $a;
    }

    /** Python's int in arithmetic: an int, or a bool counted as 0 / 1. Anything else is a type error. */
    public static function of(mixed $v): int|BigInt
    {
        if (is_int($v) || $v instanceof BigInt) {
            return $v;
        }
        if (is_bool($v)) {
            return $v ? 1 : 0;
        }
        throw new \TypeError('expected an integer, got ' . get_debug_type($v));
    }

    /** @return array{bool,string} negative?, magnitude digits */
    private static function split(string $s): array
    {
        return $s[0] === '-' ? [true, substr($s, 1)] : [false, $s];
    }

    private static function cmpMag(string $a, string $b): int
    {
        return strlen($a) !== strlen($b) ? strlen($a) <=> strlen($b) : (strcmp($a, $b) <=> 0);
    }

    private static function addMag(string $a, string $b): string
    {
        $n = max(strlen($a), strlen($b));
        $a = str_pad($a, $n, '0', STR_PAD_LEFT);
        $b = str_pad($b, $n, '0', STR_PAD_LEFT);
        $out = '';
        $carry = 0;
        for ($i = $n - 1; $i >= 0; $i--) {
            $d = (ord($a[$i]) - 48) + (ord($b[$i]) - 48) + $carry;
            $carry = intdiv($d, 10);
            $out .= chr(48 + $d % 10);
        }
        if ($carry) {
            $out .= '1';
        }
        return strrev($out);
    }

    /** $a >= $b */
    private static function subMag(string $a, string $b): string
    {
        $n = strlen($a);
        $b = str_pad($b, $n, '0', STR_PAD_LEFT);
        $out = '';
        $borrow = 0;
        for ($i = $n - 1; $i >= 0; $i--) {
            $d = (ord($a[$i]) - 48) - (ord($b[$i]) - 48) - $borrow;
            $borrow = $d < 0 ? 1 : 0;
            $out .= chr(48 + ($d < 0 ? $d + 10 : $d));
        }
        return strrev($out);
    }
}
