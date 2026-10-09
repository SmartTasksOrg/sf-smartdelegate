<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * JSON reading and writing with the fidelity the engine needs. PHP's own
 * json_decode()/json_encode() lose things the reference keeps:
 *
 *   {} vs []           objects are JsonObject, lists are PHP list arrays
 *   "123" keys         stay strings
 *   1 vs 1.0           int vs float, both written back as they came
 *   integers > 64 bit  BigInt (exact), never a float and never a string
 *   output             the three forms Python's json.dumps is used in by the
 *                      reference: compact, spaced, indented; \uXXXX or UTF-8
 *
 * Decoding accepts what Python's json.loads accepts, with one exception: an
 * unpaired UTF-16 surrogate escape is refused.
 */
final class Json
{
    /** Deepest nesting accepted, in text and in native PHP input. */
    public const MAX_DEPTH = 512;

    private const ESC = [
        '"' => '\\"', '\\' => '\\\\', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t', "\x08" => '\\b', "\x0c" => '\\f',
        "\x00" => '\\u0000', "\x01" => '\\u0001', "\x02" => '\\u0002', "\x03" => '\\u0003', "\x04" => '\\u0004',
        "\x05" => '\\u0005', "\x06" => '\\u0006', "\x07" => '\\u0007', "\x0b" => '\\u000b', "\x0e" => '\\u000e',
        "\x0f" => '\\u000f', "\x10" => '\\u0010', "\x11" => '\\u0011', "\x12" => '\\u0012', "\x13" => '\\u0013',
        "\x14" => '\\u0014', "\x15" => '\\u0015', "\x16" => '\\u0016', "\x17" => '\\u0017', "\x18" => '\\u0018',
        "\x19" => '\\u0019', "\x1a" => '\\u001a', "\x1b" => '\\u001b', "\x1c" => '\\u001c', "\x1d" => '\\u001d',
        "\x1e" => '\\u001e', "\x1f" => '\\u001f',
    ];

    // ---- decoding ------------------------------------------------------------

    /** JSON text -> value. Throws JsonError. */
    public static function decode(string $text): mixed
    {
        if (!mb_check_encoding($text, 'UTF-8')) {
            throw new JsonError('the text is not valid UTF-8');
        }
        $i = 0;
        $v = self::value($text, $i, 0);
        $i += strspn($text, " \t\n\r", $i);
        if ($i !== strlen($text)) {
            throw new JsonError("extra data at byte $i");
        }
        return $v;
    }

    /** As decode(), for raw bytes read from a file or a socket: a UTF-8 byte order mark is skipped. */
    public static function decodeBytes(string $bytes): mixed
    {
        return self::decode(strncmp($bytes, "\xEF\xBB\xBF", 3) === 0 ? substr($bytes, 3) : $bytes);
    }

    private static function value(string $s, int &$i, int $depth): mixed
    {
        $i += strspn($s, " \t\n\r", $i);
        $c = $s[$i] ?? '';
        if ($c === '"') {
            return self::str($s, $i);
        }
        if ($c === '{') {
            if ($depth >= self::MAX_DEPTH) {
                throw new JsonError('nested too deeply');
            }
            $i++;
            $m = [];
            $i += strspn($s, " \t\n\r", $i);
            if (($s[$i] ?? '') === '}') {
                $i++;
                return new JsonObject();
            }
            while (true) {
                $i += strspn($s, " \t\n\r", $i);
                if (($s[$i] ?? '') !== '"') {
                    throw new JsonError("expected a property name at byte $i");
                }
                $k = self::str($s, $i);
                $i += strspn($s, " \t\n\r", $i);
                if (($s[$i] ?? '') !== ':') {
                    throw new JsonError("expected ':' at byte $i");
                }
                $i++;
                $m[$k] = self::value($s, $i, $depth + 1);   // a repeated key: the last value wins
                $i += strspn($s, " \t\n\r", $i);
                $c = $s[$i] ?? '';
                $i++;
                if ($c === '}') {
                    return new JsonObject($m);
                }
                if ($c !== ',') {
                    throw new JsonError("expected ',' or '}' at byte " . ($i - 1));
                }
            }
        }
        if ($c === '[') {
            if ($depth >= self::MAX_DEPTH) {
                throw new JsonError('nested too deeply');
            }
            $i++;
            $out = [];
            $i += strspn($s, " \t\n\r", $i);
            if (($s[$i] ?? '') === ']') {
                $i++;
                return $out;
            }
            while (true) {
                $out[] = self::value($s, $i, $depth + 1);
                $i += strspn($s, " \t\n\r", $i);
                $c = $s[$i] ?? '';
                $i++;
                if ($c === ']') {
                    return $out;
                }
                if ($c !== ',') {
                    throw new JsonError("expected ',' or ']' at byte " . ($i - 1));
                }
            }
        }
        if (preg_match('/\G-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?/', $s, $m, 0, $i) === 1) {
            $i += strlen($m[0]);
            if (!isset($m[1]) && !isset($m[2]) || (($m[1] ?? '') === '' && ($m[2] ?? '') === '')) {
                return Num::parse($m[0]);
            }
            return (float) $m[0];
        }
        foreach ([['true', true], ['false', false], ['null', null], ['NaN', NAN], ['Infinity', INF], ['-Infinity', -INF]] as [$word, $val]) {
            if (substr_compare($s, $word, $i, strlen($word)) === 0) {
                $i += strlen($word);
                return $val;
            }
        }
        throw new JsonError($i >= strlen($s) ? 'unexpected end of JSON text' : "unexpected character at byte $i");
    }

    private static function str(string $s, int &$i): string
    {
        // fast path: no escapes
        if (preg_match('/\G"([^"\\\\\x00-\x1f]*+)"/', $s, $m, 0, $i) === 1) {
            $i += strlen($m[0]);
            return $m[1];
        }
        $i++;
        $out = '';
        $n = strlen($s);
        while (true) {
            $run = strcspn($s, "\"\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", $i);
            $out .= substr($s, $i, $run);
            $i += $run;
            if ($i >= $n) {
                throw new JsonError('unterminated string');
            }
            $c = $s[$i++];
            if ($c === '"') {
                return $out;
            }
            if ($c !== '\\') {
                throw new JsonError('control character in a string at byte ' . ($i - 1));
            }
            $e = $s[$i++] ?? '';
            switch ($e) {
                case '"': case '\\': case '/':
                    $out .= $e;
                    break;
                case 'b': $out .= "\x08"; break;
                case 'f': $out .= "\x0c"; break;
                case 'n': $out .= "\n"; break;
                case 'r': $out .= "\r"; break;
                case 't': $out .= "\t"; break;
                case 'u':
                    $cp = self::hex4($s, $i);
                    if ($cp >= 0xD800 && $cp <= 0xDBFF && substr($s, $i, 2) === '\\u') {
                        $j = $i + 2;
                        $lo = self::hex4($s, $j);
                        if ($lo >= 0xDC00 && $lo <= 0xDFFF) {
                            $cp = 0x10000 + (($cp - 0xD800) << 10) + ($lo - 0xDC00);
                            $i = $j;
                        }
                    }
                    if ($cp >= 0xD800 && $cp <= 0xDFFF) {
                        throw new JsonError('unpaired UTF-16 surrogate in a string');
                    }
                    $out .= mb_chr($cp, 'UTF-8');
                    break;
                default:
                    throw new JsonError('invalid escape at byte ' . ($i - 1));
            }
        }
    }

    private static function hex4(string $s, int &$i): int
    {
        $h = substr($s, $i, 4);
        if (strlen($h) !== 4 || !ctype_xdigit($h)) {
            throw new JsonError("invalid \\u escape at byte $i");
        }
        $i += 4;
        return (int) hexdec($h);
    }

    // ---- encoding ------------------------------------------------------------

    /**
     * Value -> JSON text, as Python's json.dumps writes it.
     *
     * @param bool     $ascii   write non-ASCII characters as \uXXXX (json.dumps default) or as themselves
     * @param bool     $sort    sort object keys by Unicode code point
     * @param string   $itemSep between items; ignored when $indent is set
     * @param string   $keySep  between key and value
     * @param int|null $indent  spaces per level, or null for one line
     */
    public static function encode(mixed $v, bool $ascii = true, bool $sort = false, string $itemSep = ', ', string $keySep = ': ', ?int $indent = null): string
    {
        $out = '';
        self::write($out, $v, $ascii, $sort, $itemSep, $keySep, $indent, 0);
        return $out;
    }

    /** One line, no spaces, \uXXXX escapes: json.dumps(v, separators=(",", ":")). */
    public static function compact(mixed $v, bool $ascii = true): string
    {
        return self::encode($v, $ascii, false, ',', ':');
    }

    /** Indented by two: json.dumps(v, indent=2, ensure_ascii=...). */
    public static function pretty(mixed $v, bool $ascii = false): string
    {
        return self::encode($v, $ascii, false, ',', ': ', 2);
    }

    private static function write(string &$out, mixed $v, bool $ascii, bool $sort, string $itemSep, string $keySep, ?int $indent, int $level): void
    {
        if (is_string($v)) {
            $out .= self::quote($v, $ascii);
        } elseif (is_int($v)) {
            $out .= $v;
        } elseif ($v === null) {
            $out .= 'null';
        } elseif (is_bool($v)) {
            $out .= $v ? 'true' : 'false';
        } elseif ($v instanceof JsonObject || is_array($v)) {
            if ($level > self::MAX_DEPTH + 8) {
                throw new JsonError('nested too deeply');
            }
            $isObj = $v instanceof JsonObject;
            $items = $isObj ? $v->m : $v;
            if ($items === []) {
                $out .= $isObj ? '{}' : '[]';
                return;
            }
            if (!$isObj && !array_is_list($items)) {
                throw new JsonError('a PHP array with keys is not a JSON value; use JsonObject');
            }
            if ($indent === null) {
                $open = '';
                $sep = $itemSep;
                $close = '';
            } else {
                $open = "\n" . str_repeat(' ', $indent * ($level + 1));
                $sep = ',' . $open;
                $close = "\n" . str_repeat(' ', $indent * $level);
            }
            $out .= ($isObj ? '{' : '[') . $open;
            $first = true;
            if ($isObj) {
                $keys = array_map('strval', array_keys($items));
                if ($sort) {
                    sort($keys, SORT_STRING);   // UTF-8 byte order is Unicode code point order
                }
                foreach ($keys as $k) {
                    if (!$first) {
                        $out .= $sep;
                    }
                    $first = false;
                    $out .= self::quote($k, $ascii) . $keySep;
                    self::write($out, $items[$k], $ascii, $sort, $itemSep, $keySep, $indent, $level + 1);
                }
            } else {
                foreach ($items as $x) {
                    if (!$first) {
                        $out .= $sep;
                    }
                    $first = false;
                    self::write($out, $x, $ascii, $sort, $itemSep, $keySep, $indent, $level + 1);
                }
            }
            $out .= $close . ($isObj ? '}' : ']');
        } elseif ($v instanceof BigInt) {
            $out .= $v->digits;
        } elseif (is_float($v)) {
            $out .= self::floatRepr($v);
        } else {
            throw new JsonError(get_debug_type($v) . ' is not a JSON value');
        }
    }

    public static function quote(string $s, bool $ascii): string
    {
        if (preg_match('/[^\x20\x21\x23-\x5b\x5d-\x7e]/', $s) !== 1) {
            return '"' . $s . '"';
        }
        $s = strtr($s, self::ESC);
        if ($ascii) {
            $s = preg_replace_callback('/[\x{7f}-\x{10ffff}]/u', static function (array $m): string {
                $cp = mb_ord($m[0], 'UTF-8');
                if ($cp > 0xFFFF) {
                    $cp -= 0x10000;
                    return sprintf('\\u%04x\\u%04x', 0xD800 + ($cp >> 10), 0xDC00 + ($cp & 0x3FF));
                }
                return sprintf('\\u%04x', $cp);
            }, $s);
            if ($s === null) {
                throw new JsonError('a string is not valid UTF-8');
            }
        } elseif (!mb_check_encoding($s, 'UTF-8')) {
            throw new JsonError('a string is not valid UTF-8');
        }
        return '"' . $s . '"';
    }

    /** Python's repr() of a float, which is what json.dumps writes. */
    public static function floatRepr(float $f): string
    {
        if (is_nan($f)) {
            return 'NaN';
        }
        if (is_infinite($f)) {
            return $f > 0 ? 'Infinity' : '-Infinity';
        }
        if ($f == 0.0) {
            return fdiv(1.0, $f) < 0 ? '-0.0' : '0.0';
        }
        // shortest digits that read back as the same float
        for ($p = 0; $p <= 16; $p++) {
            $e = sprintf("%.{$p}e", $f);
            if ((float) $e === $f) {
                break;
            }
        }
        [$mant, $exp] = explode('e', $e);
        $exp = (int) $exp;
        $neg = $mant[0] === '-';
        $digits = rtrim(str_replace(['-', '.'], '', $mant), '0');
        if ($digits === '') {
            $digits = '0';
        }
        $n = strlen($digits);
        if ($exp < -4 || $exp >= 16) {
            $r = $digits[0] . ($n > 1 ? '.' . substr($digits, 1) : '') . 'e' . ($exp < 0 ? '-' : '+') . str_pad((string) abs($exp), 2, '0', STR_PAD_LEFT);
        } elseif ($exp < 0) {
            $r = '0.' . str_repeat('0', -$exp - 1) . $digits;
        } elseif ($n <= $exp + 1) {
            $r = $digits . str_repeat('0', $exp + 1 - $n) . '.0';
        } else {
            $r = substr($digits, 0, $exp + 1) . '.' . substr($digits, $exp + 1);
        }
        return ($neg ? '-' : '') . $r;
    }

    // ---- native PHP data -----------------------------------------------------

    /**
     * Native PHP data -> the JSON model. An associative array or a stdClass
     * becomes a JsonObject; a list array stays a list. AN EMPTY PHP ARRAY IS
     * AN EMPTY LIST: write `new \stdClass` (or `new JsonObject`) for `{}`.
     * Throws JsonError for anything that has no JSON form.
     */
    public static function fromNative(mixed $v, int $depth = 0): mixed
    {
        if (is_string($v)) {
            if (!mb_check_encoding($v, 'UTF-8')) {
                throw new JsonError('a string is not valid UTF-8');
            }
            return $v;
        }
        if ($v === null || is_scalar($v) || $v instanceof BigInt) {
            return $v;
        }
        if ($depth >= self::MAX_DEPTH) {
            throw new JsonError('nested too deeply');
        }
        if ($v instanceof JsonObject) {
            $v = $v->m;
            $isObj = true;
        } elseif ($v instanceof \stdClass) {
            $v = (array) $v;
            $isObj = true;
        } elseif ($v instanceof \JsonSerializable) {
            return self::fromNative($v->jsonSerialize(), $depth + 1);
        } elseif (is_array($v)) {
            $isObj = !array_is_list($v);
        } else {
            throw new JsonError(get_debug_type($v) . ' is not a JSON value');
        }
        $out = [];
        foreach ($v as $k => $x) {
            if ($isObj && is_string($k) && !mb_check_encoding($k, 'UTF-8')) {
                throw new JsonError('a key is not valid UTF-8');
            }
            $out[$k] = self::fromNative($x, $depth + 1);
        }
        return $isObj ? new JsonObject($out) : $out;
    }

    /** The JSON model -> plain PHP arrays. Lossy ({} and [] both become []); for display and quick tests. */
    public static function toNative(mixed $v): mixed
    {
        if ($v instanceof JsonObject) {
            return $v->toArray();
        }
        if (is_array($v)) {
            return array_map([self::class, 'toNative'], $v);
        }
        return $v;
    }

    /** A copy that shares no JsonObject with the original. */
    public static function deepCopy(mixed $v): mixed
    {
        if ($v instanceof JsonObject) {
            $out = [];
            foreach ($v->m as $k => $x) {
                $out[$k] = is_array($x) || $x instanceof JsonObject ? self::deepCopy($x) : $x;
            }
            return new JsonObject($out);
        }
        if (is_array($v)) {
            foreach ($v as $k => $x) {
                if (is_array($x) || $x instanceof JsonObject) {
                    $v[$k] = self::deepCopy($x);
                }
            }
        }
        return $v;
    }

    // ---- Python semantics the reference relies on ------------------------------

    /** Python's `a == b` on JSON values: 1 == 1.0 == True, containers compare by content. */
    public static function pyEq(mixed $a, mixed $b): bool
    {
        if (is_string($a) || is_string($b)) {
            return $a === $b;
        }
        if ($a === null || $b === null) {
            return $a === $b;
        }
        if ($a instanceof JsonObject || $b instanceof JsonObject) {
            if (!($a instanceof JsonObject && $b instanceof JsonObject) || count($a->m) !== count($b->m)) {
                return false;
            }
            foreach ($a->m as $k => $x) {
                if (!array_key_exists($k, $b->m) || !self::pyEq($x, $b->m[$k])) {
                    return false;
                }
            }
            return true;
        }
        if (is_array($a) || is_array($b)) {
            if (!is_array($a) || !is_array($b) || count($a) !== count($b)) {
                return false;
            }
            foreach ($a as $k => $x) {
                if (!array_key_exists($k, $b) || !self::pyEq($x, $b[$k])) {
                    return false;
                }
            }
            return true;
        }
        // numbers: bool, int, BigInt, float
        if (is_bool($a)) {
            $a = (int) $a;
        }
        if (is_bool($b)) {
            $b = (int) $b;
        }
        if (is_float($a) || is_float($b)) {
            if ($a instanceof BigInt || $b instanceof BigInt) {
                return false;   // an exact integer beyond 2^63 against a float: compare as written
            }
            if (is_int($a) && is_int($b)) {
                return $a === $b;
            }
            $f = is_float($a) ? $a : $b;
            $n = is_float($a) ? $b : $a;
            if (is_float($n)) {
                return $f == $n;
            }
            // float against int, exactly (a float above 2^53 must not be rounded into equality)
            return is_finite($f) && floor($f) == $f && abs($f) < 9.2e18 && (int) $f === $n;
        }
        if ($a instanceof BigInt || $b instanceof BigInt) {
            return $a instanceof BigInt && $b instanceof BigInt && $a->digits === $b->digits;
        }
        return $a === $b;
    }

    /** Python's type of a JSON value, for `type(a) is type(b)`. */
    public static function pyType(mixed $v): string
    {
        return match (true) {
            $v === null => 'none',
            is_bool($v) => 'bool',
            is_int($v), $v instanceof BigInt => 'int',
            is_float($v) => 'float',
            is_string($v) => 'str',
            is_array($v) => 'list',
            $v instanceof JsonObject => 'dict',
            default => get_debug_type($v),
        };
    }

    /** Python truthiness: None, False, 0, 0.0, "", [] and {} are false. */
    public static function truthy(mixed $v): bool
    {
        if ($v instanceof JsonObject) {
            return $v->m !== [];
        }
        if ($v instanceof BigInt) {
            return true;
        }
        if (is_string($v)) {
            return $v !== '';
        }
        return (bool) $v;
    }

    /** UTF-8 of the non-ASCII characters Python's str.isspace() accepts. */
    private const WIDE_SPACE = [
        "\xc2\x85", "\xc2\xa0", "\xe1\x9a\x80", "\xe2\x80\x80", "\xe2\x80\x81", "\xe2\x80\x82", "\xe2\x80\x83", "\xe2\x80\x84", "\xe2\x80\x85",
        "\xe2\x80\x86", "\xe2\x80\x87", "\xe2\x80\x88", "\xe2\x80\x89", "\xe2\x80\x8a", "\xe2\x80\xa8", "\xe2\x80\xa9", "\xe2\x80\xaf", "\xe2\x81\x9f",
        "\xe3\x80\x80",
    ];
    private const ASCII_SPACE = " \t\n\r\x0b\x0c\x1c\x1d\x1e\x1f";

    /** Python's str.strip(): Unicode white space, and not NUL. Linear time; no regular expression. */
    public static function pyStrip(string $s): string
    {
        $i = 0;
        $n = strlen($s);
        while ($i < $n) {
            $k = strspn($s, self::ASCII_SPACE, $i);
            if ($k > 0) {
                $i += $k;
                continue;
            }
            $w = ord($s[$i]) < 0xC2 ? 0 : self::wideSpaceAt($s, $i);
            if ($w === 0) {
                break;
            }
            $i += $w;
        }
        while ($n > $i) {
            if (strpos(self::ASCII_SPACE, $s[$n - 1]) !== false) {
                $n--;
                continue;
            }
            $w = 0;
            if (ord($s[$n - 1]) >= 0x80) {
                foreach ([2, 3] as $len) {
                    if ($n - $len >= $i && self::wideSpaceAt($s, $n - $len) === $len) {
                        $w = $len;
                        break;
                    }
                }
            }
            if ($w === 0) {
                break;
            }
            $n -= $w;
        }
        return substr($s, $i, $n - $i);
    }

    /** Length in bytes of the non-ASCII white space character at $i, or 0. */
    private static function wideSpaceAt(string $s, int $i): int
    {
        foreach (self::WIDE_SPACE as $w) {
            if (substr_compare($s, $w, $i, strlen($w)) === 0) {
                return strlen($w);
            }
        }
        return 0;
    }
}
