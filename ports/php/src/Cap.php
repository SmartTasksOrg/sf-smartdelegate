<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * A capability. actions / resources: names with an optional single trailing
 * `*`. resources are `<path>/<id>`. deny_labels / deny_fields: what this
 * token can never see, whatever policy says. budget: currency -> total spend
 * in minor units.
 */
final class Cap
{
    /** @var list<string> */
    public array $actions;
    /** @var list<string> */
    public array $resources;
    /** @var list<string> */
    public array $denyLabels;
    /** @var list<string> */
    public array $denyFields;
    /** @var array<array-key,int|BigInt> currency => amount; cast keys to string when reading them */
    public array $budget;

    public function __construct(mixed $actions = null, mixed $resources = null, mixed $denyLabels = null, mixed $denyFields = null, mixed $budget = null)
    {
        $this->actions = self::strList($actions, 'cap.actions');
        $this->resources = self::strList($resources, 'cap.resources');
        $this->denyLabels = self::strList($denyLabels, 'cap.deny_labels');
        $this->denyFields = self::strList($denyFields, 'cap.deny_fields');
        $b = [];
        if (Json::truthy($budget)) {   // like the reference, anything empty ({} or [] or 0) is "no budget"
            if (!$budget instanceof JsonObject) {
                throw new EngineError('invalid_cap', 'cap.budget must map currency to an integer amount in minor units');
            }
            foreach ($budget->m as $k => $v) {
                if (!Num::isInt($v)) {   // 1.0 is a float and true is a bool: neither is an amount
                    throw new EngineError('invalid_cap', 'cap.budget must map currency to an integer amount in minor units');
                }
                $b[$k] = $v;
            }
        }
        $this->budget = $b;
    }

    private static function strList(mixed $v, string $what): array
    {
        if ($v === null) {
            return [];
        }
        if (!is_array($v)) {
            throw new EngineError('invalid_cap', "$what must be a list of strings");
        }
        foreach ($v as $x) {
            if (!is_string($x)) {
                throw new EngineError('invalid_cap', "$what must be a list of strings");
            }
        }
        return $v;
    }

    public static function fromJson(mixed $v): self
    {
        if (!$v instanceof JsonObject) {
            throw new EngineError('invalid_cap', 'cap must be an object');
        }
        $unknown = array_values(array_diff($v->keys(), ['actions', 'resources', 'deny_labels', 'deny_fields', 'budget']));
        if ($unknown) {
            // a misspelt key must not silently become "no restriction"
            sort($unknown, SORT_STRING);
            throw new EngineError('invalid_cap', 'unknown cap field(s): ' . implode(', ', $unknown));
        }
        return new self($v->get('actions'), $v->get('resources'), $v->get('deny_labels'), $v->get('deny_fields'), $v->get('budget'));
    }

    public static function unrestricted(): self
    {
        return new self(['*'], ['*']);
    }

    public function toJson(): JsonObject
    {
        return new JsonObject(['actions' => $this->actions, 'resources' => $this->resources, 'deny_labels' => $this->denyLabels,
            'deny_fields' => $this->denyFields, 'budget' => new JsonObject($this->budget)]);
    }

    public function validate(): void
    {
        foreach ([...$this->actions, ...$this->resources] as $p) {
            if ($p === '' || str_contains(substr($p, 0, -1), '*')) {
                throw new EngineError('invalid_cap', "pattern '$p': only one trailing * is allowed");
            }
        }
        foreach ($this->budget as $v) {
            if (Num::cmp($v, 0) < 0) {
                throw new EngineError('invalid_cap', 'budget cannot be negative');
            }
        }
    }

    public function allowsAction(string $action): bool
    {
        foreach ($this->actions as $p) {
            if (self::matches($p, $action)) {
                return true;
            }
        }
        return false;
    }

    public function allowsResource(string $path, string $id): bool
    {
        $s = $path . '/' . $id;
        foreach ($this->resources as $p) {
            if (self::matches($p, $s)) {
                return true;
            }
        }
        return false;
    }

    /** Throws `widening` unless this capability grants nothing the parent does not. */
    public function checkNarrowerThan(Cap $parent): void
    {
        foreach ($this->actions as $a) {
            if (!self::coveredBy($parent->actions, $a)) {
                throw new EngineError('widening', "action '$a' is not covered by the parent token");
            }
        }
        foreach ($this->resources as $r) {
            if (!self::coveredBy($parent->resources, $r)) {
                throw new EngineError('widening', "resource '$r' is not covered by the parent token");
            }
        }
        foreach ($parent->denyLabels as $l) {
            if (!in_array($l, $this->denyLabels, true)) {
                throw new EngineError('widening', "label '$l' is denied by the parent and must stay denied");
            }
        }
        foreach ($parent->denyFields as $f) {
            if (!in_array($f, $this->denyFields, true)) {
                throw new EngineError('widening', "field '$f' is denied by the parent and must stay denied");
            }
        }
        foreach ($this->budget as $cur => $amount) {
            if (!array_key_exists($cur, $parent->budget)) {
                throw new EngineError('widening', "the parent token has no $cur budget to pass on");
            }
            if (Num::cmp($amount, $parent->budget[$cur]) > 0) {
                throw new EngineError('widening', 'budget ' . Num::str($amount) . " $cur exceeds the parent's " . Num::str($parent->budget[$cur]));
            }
        }
    }

    public static function matches(string $pattern, string $s): bool
    {
        return str_ends_with($pattern, '*') ? str_starts_with($s, substr($pattern, 0, -1)) : $pattern === $s;
    }

    private static function coveredBy(array $parents, string $child): bool
    {
        foreach ($parents as $p) {
            if (self::covers($p, $child)) {
                return true;
            }
        }
        return false;
    }

    /** Does `parent` cover every string that `child` covers? */
    private static function covers(string $parent, string $child): bool
    {
        if (str_ends_with($parent, '*')) {
            $prefix = substr($parent, 0, -1);
            return str_starts_with(str_ends_with($child, '*') ? rtrim($child, '*') : $child, $prefix);
        }
        return !str_ends_with($child, '*') && $parent === $child;
    }
}
