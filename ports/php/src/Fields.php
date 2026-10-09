<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * Applying a field mask and a row filter to JSON data.
 *
 * Field paths are relative to the resource: `email`, `address.zip`,
 * `orders[].total`. `[]` stands for "each element of this array".
 *
 * Rules (fail closed):
 *   - a denied path is dropped, or replaced by "[REDACTED]" when the catalog
 *     says `mask: redact`; its whole subtree goes with it
 *   - an allowed path is kept; children that have their own catalog entry are
 *     still checked one by one, other children are kept with the parent
 *   - a path the catalog does not list, under no allowed parent, is dropped
 *
 * A record is a JsonObject and a list of records is a PHP list; a PHP list is
 * never taken for a record.
 */
final class Fields
{
    public const REDACTED = '[REDACTED]';
    public const ALLOW = 'allow';
    public const DENY = 'deny';
    public const REDACT = 'redact';

    /** @param array<array-key,string> $status */
    private static function hasChildren(array $status, string $path): bool
    {
        $a = $path . '.';
        $b = $path . '[]';
        $n = strlen($a);
        $m = strlen($b);
        foreach ($status as $k => $_) {
            $k = (string) $k;
            if (strncmp($k, $a, $n) === 0 || strncmp($k, $b, $m) === 0) {
                return true;
            }
        }
        return false;
    }

    /** @return array{bool,mixed} keep?, value */
    private static function walkValue(mixed $v, string $path, bool $inherit, array $status, array &$masked): array
    {
        if ($v instanceof JsonObject) {
            return [true, self::walkObject($v, $path, $inherit, $status, $masked)];
        }
        if (is_array($v)) {
            $p = $path . '[]';
            $st = $status[$p] ?? null;
            $out = [];
            foreach ($v as $el) {
                if ($st === self::DENY) {
                    $masked[$p] = true;
                } elseif ($st === self::REDACT) {
                    $masked[$p] = true;
                    $out[] = self::REDACTED;
                } elseif ($st === self::ALLOW) {
                    [$keep, $x] = self::walkValue($el, $p, true, $status, $masked);
                    if ($keep) {
                        $out[] = $x;
                    }
                } elseif ($el instanceof JsonObject || is_array($el)) {
                    [$keep, $x] = self::walkValue($el, $p, $inherit, $status, $masked);
                    if ($keep) {
                        $out[] = $x;
                    }
                } elseif ($inherit) {
                    $out[] = $el;
                } else {
                    $masked[$p] = true;
                }
            }
            return [true, $out];
        }
        return $inherit ? [true, $v] : [false, null];
    }

    private static function walkObject(JsonObject $m, string $prefix, bool $inherit, array $status, array &$masked): JsonObject
    {
        $out = [];
        foreach ($m->m as $k => $v) {
            $p = $prefix !== '' ? $prefix . '.' . $k : (string) $k;
            $st = $status[$p] ?? null;
            if ($st === self::DENY) {
                $masked[$p] = true;
            } elseif ($st === self::REDACT) {
                $masked[$p] = true;
                $out[$k] = self::REDACTED;
            } elseif ($st === self::ALLOW) {
                if (self::hasChildren($status, $p)) {
                    [$keep, $x] = self::walkValue($v, $p, true, $status, $masked);
                    if ($keep) {
                        $out[$k] = $x;
                    }
                } else {
                    $out[$k] = $v;
                }
            } elseif ($inherit && !self::hasChildren($status, $p)) {
                $out[$k] = $v;
            } elseif (($v instanceof JsonObject || is_array($v)) && self::hasChildren($status, $p)) {
                [$keep, $x] = self::walkValue($v, $p, $inherit, $status, $masked);
                if ($keep) {
                    $out[$k] = $x;
                }
            } elseif ($inherit) {
                $out[$k] = $v;
            } else {
                $masked[$p] = true;
            }
        }
        return new JsonObject($out);
    }

    /** JSON equality as the reference has it: true is not 1, 1 is not 1.0. */
    private static function same(mixed $a, mixed $b): bool
    {
        return Json::pyType($a) === Json::pyType($b) && Json::pyEq($a, $b);
    }

    /** @param list<JsonObject> $rowFilter */
    private static function rowMatches(mixed $row, array $rowFilter): bool
    {
        foreach ($rowFilter as $c) {
            $col = $c->get('column');
            if (!$row instanceof JsonObject || !is_string($col) || !$row->has($col) || !self::same($row->get($col), $c->get('value'))) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param mixed                    $data      one record (JsonObject) or a list of records
     * @param array<array-key,string>  $status    field path => allow | deny | redact
     * @param list<JsonObject>         $rowFilter [{column, op, value}]
     * @return array{mixed,list<string>,int} data, masked paths (sorted), rows dropped
     */
    public static function apply(mixed $data, array $status, array $rowFilter): array
    {
        $masked = [];
        $dropped = 0;
        if (is_array($data)) {
            $out = [];
            foreach ($data as $r) {
                if ($r instanceof JsonObject && self::rowMatches($r, $rowFilter)) {
                    $out[] = self::walkObject($r, '', false, $status, $masked);
                } else {
                    $dropped++;
                }
            }
        } elseif ($data instanceof JsonObject) {
            if (self::rowMatches($data, $rowFilter)) {
                $out = self::walkObject($data, '', false, $status, $masked);
            } else {
                $out = null;
                $dropped = 1;
            }
        } else {
            // a bare scalar has no field identity, so nothing can authorise it
            $out = null;
            $dropped = 1;
        }
        $paths = array_map('strval', array_keys($masked));
        sort($paths, SORT_STRING);
        return [$out, $paths, $dropped];
    }
}
