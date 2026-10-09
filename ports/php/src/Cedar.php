<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * Evaluator for Cedar's JSON policy form (the portable subset).
 *
 * Policies are written in Cedar and compiled to JSON by the Cedar toolchain
 * (`smartdelegate bundle compile` in the Rust port). This class evaluates
 * that JSON directly. What it must do is fixed by
 * spec/conformance/eval/cases.json, whose expected answers come from the real
 * Cedar engine. Anything outside the subset is refused when the bundle loads.
 *
 * Cedar values in PHP: bool, int (64-bit long), string, Entity, CedarSet, and
 * a PHP array for a record (attribute name => value).
 *
 *   - a policy whose condition errors is skipped and reported, permit or forbid
 *   - `&&` / `||` short-circuit, but the side that is evaluated must be boolean
 *   - `==` across types is false; `<` across types is an error
 *   - arithmetic is 64-bit and overflow is an error (PHP would silently
 *     produce a float; every result is checked)
 *   - sets ignore order and duplicates
 *   - an entity missing from the store has no attributes (`.` errors, `has`
 *     is false) and is `in` only itself
 */
final class Cedar
{
    private const BINARY = ['==' => 1, '!=' => 1, '<' => 1, '<=' => 1, '>' => 1, '>=' => 1, '&&' => 1, '||' => 1, '+' => 1, '-' => 1,
        '*' => 1, 'in' => 1, 'contains' => 1, 'containsAll' => 1, 'containsAny' => 1];
    private const UNARY = ['!' => 1, 'neg' => 1, 'isEmpty' => 1];

    public static function validType(mixed $name): bool
    {
        // /D: a full match. Without it `$` would let one trailing newline through.
        return is_string($name) && preg_match('/^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$/D', $name) === 1;
    }

    /** An identity for a value; equal values have equal keys. */
    public static function key(mixed $v): string
    {
        if (is_bool($v)) {
            return $v ? 'b1' : 'b0';
        }
        if (is_int($v)) {
            return 'l' . $v;
        }
        if (is_string($v)) {
            return 's' . $v;
        }
        if ($v instanceof Entity) {
            return 'e' . strlen($v->type) . ':' . $v->type . $v->id;
        }
        if ($v instanceof CedarSet) {
            $keys = array_map('strval', array_keys($v->items));
            sort($keys, SORT_STRING);
            $out = 'S';
            foreach ($keys as $k) {
                $out .= strlen($k) . ':' . $k;
            }
            return $out;
        }
        if (is_array($v)) {
            $names = array_map('strval', array_keys($v));
            sort($names, SORT_STRING);
            $out = 'R';
            foreach ($names as $n) {
                $k = self::key($v[$n]);
                $out .= strlen($n) . ':' . $n . strlen($k) . ':' . $k;
            }
            return $out;
        }
        throw new EvalError('not a Cedar value: ' . get_debug_type($v));
    }

    /**
     * JSON -> Cedar value, for entity attributes, context and literals.
     * Lists are sets; {"__entity": {type, id}} is an entity reference.
     *
     * @throws CedarValueError
     */
    public static function fromJson(mixed $v): mixed
    {
        if (is_bool($v) || is_string($v) || is_int($v)) {
            return $v;
        }
        if ($v instanceof BigInt) {
            throw new CedarValueError('integer does not fit in 64 bits');
        }
        if (is_float($v)) {
            throw new CedarValueError('floating-point numbers are not Cedar values');
        }
        if ($v === null) {
            throw new CedarValueError('null is not a Cedar value');
        }
        if (is_array($v)) {
            $items = [];
            foreach ($v as $x) {
                $items[] = self::fromJson($x);
            }
            return new CedarSet($items);
        }
        if ($v instanceof JsonObject) {
            if ($v->has('__entity')) {
                $e = $v->get('__entity');
                if (count($v->m) !== 1 || !$e instanceof JsonObject || !self::validType($e->get('type')) || !is_string($e->get('id'))) {
                    throw new CedarValueError('malformed __entity reference');
                }
                return new Entity($e->get('type'), $e->get('id'));
            }
            if ($v->has('__extn')) {
                throw new CedarValueError('extension values (decimal, ip, datetime) are outside the portable subset');
            }
            $rec = [];
            foreach ($v->m as $k => $x) {
                $rec[$k] = self::fromJson($x);
            }
            return $rec;
        }
        throw new CedarValueError('not a JSON value: ' . get_debug_type($v));
    }

    // ---- loading: reject anything outside the subset ---------------------------

    /** @throws Unsupported */
    public static function entityLit(mixed $e): Entity
    {
        if ($e instanceof JsonObject && $e->has('__entity')) {
            $e = $e->get('__entity');
        }
        if (!$e instanceof JsonObject || !self::validType($e->get('type')) || !is_string($e->get('id'))) {
            throw new Unsupported('malformed entity in policy scope');
        }
        return new Entity($e->get('type'), $e->get('id'));
    }

    private static function part(mixed $arg, string $name): mixed
    {
        if (!$arg instanceof JsonObject || !$arg->has($name)) {
            throw new Unsupported("malformed policy JSON (missing '$name')");
        }
        return $arg->get($name);
    }

    /** @throws Unsupported */
    public static function checkExpr(mixed $e): void
    {
        if (!$e instanceof JsonObject || count($e->m) !== 1) {
            throw new Unsupported('malformed expression');
        }
        $op = (string) array_key_first($e->m);
        $arg = $e->m[$op];
        if ($op === 'Value') {
            try {
                self::fromJson($arg);
            } catch (CedarValueError $err) {
                throw new Unsupported($err->getMessage());
            }
        } elseif ($op === 'Var') {
            if (!is_string($arg) || !in_array($arg, ['principal', 'action', 'resource', 'context'], true)) {
                throw new Unsupported('unknown variable');
            }
        } elseif (isset(self::BINARY[$op])) {
            self::checkExpr(self::part($arg, 'left'));
            self::checkExpr(self::part($arg, 'right'));
        } elseif (isset(self::UNARY[$op])) {
            self::checkExpr(self::part($arg, 'arg'));
        } elseif ($op === '.' || $op === 'has') {
            self::checkExpr(self::part($arg, 'left'));
            if (!is_string($arg->get('attr'))) {
                throw new Unsupported('attribute name must be a string');
            }
        } elseif ($op === 'is') {
            self::checkExpr(self::part($arg, 'left'));
            if (!self::validType($arg->get('entity_type'))) {
                throw new Unsupported('malformed entity type in `is`');
            }
            if ($arg->has('in')) {
                self::checkExpr($arg->get('in'));
            }
        } elseif ($op === 'like') {
            self::checkExpr(self::part($arg, 'left'));
            $pattern = self::part($arg, 'pattern');
            if (!is_array($pattern)) {
                throw new Unsupported('malformed like pattern');
            }
            foreach ($pattern as $part) {
                if ($part !== 'Wildcard' && !($part instanceof JsonObject && is_string($part->get('Literal')))) {
                    throw new Unsupported('malformed like pattern');
                }
            }
        } elseif ($op === 'if-then-else') {
            foreach (['if', 'then', 'else'] as $k) {
                self::checkExpr(self::part($arg, $k));
            }
        } elseif ($op === 'Set') {
            if (!is_array($arg)) {
                throw new Unsupported('malformed set literal');
            }
            foreach ($arg as $x) {
                self::checkExpr($x);
            }
        } elseif ($op === 'Record') {
            if (!$arg instanceof JsonObject) {
                throw new Unsupported('malformed record literal');
            }
            foreach ($arg->m as $x) {
                self::checkExpr($x);
            }
        } else {
            throw new Unsupported("`$op` is outside the portable Cedar subset");
        }
    }

    /** @throws Unsupported */
    public static function checkScope(mixed $scope, string $what): void
    {
        if (!$scope instanceof JsonObject) {
            throw new Unsupported("unsupported $what scope");
        }
        if ($scope->has('slot')) {
            throw new Unsupported('policy templates are not supported');
        }
        $op = $scope->get('op');
        if ($op === 'All') {
            return;
        }
        if ($op === '==') {
            self::entityLit($scope->get('entity'));
        } elseif ($op === 'in') {
            if ($scope->has('entities')) {
                if ($what !== 'action') {
                    throw new Unsupported("$what scope cannot use a list");
                }
                $list = $scope->get('entities');
                if (!is_array($list)) {
                    throw new Unsupported('malformed policy JSON (entities must be a list)');
                }
                foreach ($list as $x) {
                    self::entityLit($x);
                }
            } else {
                self::entityLit($scope->get('entity'));
            }
        } elseif ($op === 'is' && $what !== 'action') {
            if (!self::validType($scope->get('entity_type'))) {
                throw new Unsupported('malformed entity type in scope');
            }
            if ($scope->has('in')) {
                $in = $scope->get('in');
                if (!$in instanceof JsonObject) {
                    throw new Unsupported('malformed policy JSON (scope `in`)');
                }
                self::entityLit($in->get('entity'));
            }
        } else {
            throw new Unsupported("unsupported $what scope");
        }
    }

    // ---- evaluation ------------------------------------------------------------

    private static function bool(mixed $v, string $what): bool
    {
        if (!is_bool($v)) {
            throw new EvalError("$what must be a boolean");
        }
        return $v;
    }

    private static function long(mixed $v, string $what): int
    {
        if (!is_int($v)) {
            throw new EvalError("$what must be a long");
        }
        return $v;
    }

    /** PHP turns an overflowing integer operation into a float; Cedar makes it an error. */
    private static function checked(int|float $n): int
    {
        if (!is_int($n)) {
            throw new EvalError('integer overflow');
        }
        return $n;
    }

    private static function set(mixed $v, string $what): CedarSet
    {
        if (!$v instanceof CedarSet) {
            throw new EvalError("$what must be a set");
        }
        return $v;
    }

    /** Wildcard match over code points, with backtracking to the last star. */
    private static function like(string $str, array $pattern): bool
    {
        $s = mb_str_split($str, 1, 'UTF-8');
        $ns = count($s);
        $np = count($pattern);
        $i = $j = 0;
        $star = $mark = -1;
        while ($i < $ns) {
            if ($j < $np && $pattern[$j] !== 'Wildcard' && $pattern[$j]->get('Literal') === $s[$i]) {
                $i++;
                $j++;
            } elseif ($j < $np && $pattern[$j] === 'Wildcard') {
                $star = $j;
                $mark = $i;
                $j++;
            } elseif ($star !== -1) {
                $j = $star + 1;
                $mark++;
                $i = $mark;
            } else {
                return false;
            }
        }
        while ($j < $np && $pattern[$j] === 'Wildcard') {
            $j++;
        }
        return $j === $np;
    }

    /** @throws EvalError */
    public static function evaluate(JsonObject $e, Env $env): mixed
    {
        $op = (string) array_key_first($e->m);
        $a = $e->m[$op];
        if ($op === 'Value') {
            try {
                return self::fromJson($a);
            } catch (CedarValueError $err) {
                throw new EvalError($err->getMessage());
            }
        }
        if ($op === 'Var') {
            return match ($a) {
                'principal' => $env->principal,
                'action' => $env->action,
                'resource' => $env->resource,
                'context' => $env->context,
            };
        }
        if ($op === '&&') {
            if (!self::bool(self::evaluate($a->m['left'], $env), 'left of &&')) {
                return false;
            }
            return self::bool(self::evaluate($a->m['right'], $env), 'right of &&');
        }
        if ($op === '||') {
            if (self::bool(self::evaluate($a->m['left'], $env), 'left of ||')) {
                return true;
            }
            return self::bool(self::evaluate($a->m['right'], $env), 'right of ||');
        }
        if ($op === 'if-then-else') {
            return self::evaluate(self::bool(self::evaluate($a->m['if'], $env), 'if condition') ? $a->m['then'] : $a->m['else'], $env);
        }
        if ($op === '!') {
            return !self::bool(self::evaluate($a->m['arg'], $env), 'operand of !');
        }
        if ($op === 'neg') {
            return self::checked(-self::long(self::evaluate($a->m['arg'], $env), 'operand of -'));
        }
        if ($op === 'isEmpty') {
            return self::set(self::evaluate($a->m['arg'], $env), 'isEmpty receiver')->items === [];
        }
        if ($op === '.') {
            $left = self::evaluate($a->m['left'], $env);
            $attr = $a->m['attr'];
            if ($left instanceof Entity) {
                if (!$env->store->contains($left)) {
                    throw new EvalError("entity $left does not exist");
                }
                $rec = $env->store->attrs[$left->key];
            } elseif (is_array($left)) {
                $rec = $left;
            } else {
                throw new EvalError('attribute access needs an entity or a record');
            }
            if (!array_key_exists($attr, $rec)) {
                throw new EvalError("no attribute `$attr`");
            }
            return $rec[$attr];
        }
        if ($op === 'has') {
            $left = self::evaluate($a->m['left'], $env);
            if ($left instanceof Entity) {
                return array_key_exists($a->m['attr'], $env->store->attrs[$left->key] ?? []);
            }
            if (is_array($left)) {
                return array_key_exists($a->m['attr'], $left);
            }
            throw new EvalError('`has` needs an entity or a record');
        }
        if ($op === 'is') {
            $left = self::evaluate($a->m['left'], $env);
            if (!$left instanceof Entity) {
                throw new EvalError('`is` needs an entity');
            }
            if ($left->type !== $a->m['entity_type']) {
                return false;
            }
            if (array_key_exists('in', $a->m)) {
                return self::in($left, self::evaluate($a->m['in'], $env), $env);
            }
            return true;
        }
        if ($op === 'like') {
            $left = self::evaluate($a->m['left'], $env);
            if (!is_string($left)) {
                throw new EvalError('`like` needs a string');
            }
            return self::like($left, $a->m['pattern']);
        }
        if ($op === 'Set') {
            $items = [];
            foreach ($a as $x) {
                $items[] = self::evaluate($x, $env);
            }
            return new CedarSet($items);
        }
        if ($op === 'Record') {
            $rec = [];
            foreach ($a->m as $k => $x) {
                $rec[$k] = self::evaluate($x, $env);
            }
            return $rec;
        }

        if (!isset(self::BINARY[$op])) {
            throw new EvalError("unsupported operator $op");
        }
        $left = self::evaluate($a->m['left'], $env);
        $right = self::evaluate($a->m['right'], $env);
        if ($op === '==') {
            return self::key($left) === self::key($right);
        }
        if ($op === '!=') {
            return self::key($left) !== self::key($right);
        }
        if ($op === '<' || $op === '<=' || $op === '>' || $op === '>=') {
            $x = self::long($left, "left of $op");
            $y = self::long($right, "right of $op");
            return $op === '<' ? $x < $y : ($op === '<=' ? $x <= $y : ($op === '>' ? $x > $y : $x >= $y));
        }
        if ($op === '+' || $op === '-' || $op === '*') {
            $x = self::long($left, "left of $op");
            $y = self::long($right, "right of $op");
            return self::checked($op === '+' ? $x + $y : ($op === '-' ? $x - $y : $x * $y));
        }
        if ($op === 'in') {
            if (!$left instanceof Entity) {
                throw new EvalError('left of `in` must be an entity');
            }
            return self::in($left, $right, $env);
        }
        if ($op === 'contains') {
            return array_key_exists(self::key($right), self::set($left, 'contains receiver')->items);
        }
        // both operands must be sets before their contents are looked at: an
        // empty argument does not hide a receiver that is not a set
        $have = self::set($left, "$op receiver")->items;
        $want = self::set($right, "$op argument")->items;
        if ($op === 'containsAll') {
            foreach ($want as $k => $_) {
                if (!array_key_exists($k, $have)) {
                    return false;
                }
            }
            return true;
        }
        foreach ($want as $k => $_) {   // containsAny
            if (array_key_exists($k, $have)) {
                return true;
            }
        }
        return false;
    }

    private static function in(Entity $left, mixed $right, Env $env): bool
    {
        if ($right instanceof Entity) {
            return $env->store->isIn($left, $right);
        }
        if ($right instanceof CedarSet) {
            foreach ($right->items as $x) {
                if (!$x instanceof Entity) {
                    throw new EvalError('right of `in` must be an entity or a set of entities');
                }
            }
            foreach ($right->items as $x) {
                if ($env->store->isIn($left, $x)) {
                    return true;
                }
            }
            return false;
        }
        throw new EvalError('right of `in` must be an entity or a set of entities');
    }

    private static function scope(JsonObject $scope, Entity $who, Store $store): bool
    {
        $op = $scope->m['op'];
        if ($op === 'All') {
            return true;
        }
        if ($op === '==') {
            return $who->key === self::entityLit($scope->m['entity'])->key;
        }
        if ($op === 'in') {
            if (array_key_exists('entities', $scope->m)) {
                foreach ($scope->m['entities'] as $x) {
                    if ($store->isIn($who, self::entityLit($x))) {
                        return true;
                    }
                }
                return false;
            }
            return $store->isIn($who, self::entityLit($scope->m['entity']));
        }
        if ($who->type !== $scope->m['entity_type']) {   // op === 'is'
            return false;
        }
        return !array_key_exists('in', $scope->m) || $store->isIn($who, self::entityLit($scope->m['in']->m['entity']));
    }

    /** True when the policy's scope and every condition hold. @throws EvalError */
    public static function applies(Policy $p, Env $env): bool
    {
        if (!(self::scope($p->principal, $env->principal, $env->store) && self::scope($p->action, $env->action, $env->store)
            && self::scope($p->resource, $env->resource, $env->store))) {
            return false;
        }
        foreach ($p->conditions as $c) {
            $kind = $c->m['kind'];
            $v = self::bool(self::evaluate($c->m['body'], $env), "`$kind` condition");
            if ($v !== ($kind === 'when')) {
                return false;
            }
        }
        return true;
    }

    /**
     * Cedar's authorization. A satisfied forbid denies. Otherwise a satisfied
     * permit allows. Otherwise deny.
     *
     * @param array<array-key,Policy> $policies policy id => Policy
     * @return array{decision:string,reasons:list<string>,errors:list<array{string,string}>}
     */
    public static function isAuthorized(array $policies, Env $env): array
    {
        $ids = array_map('strval', array_keys($policies));
        sort($ids, SORT_STRING);
        $permits = $forbids = $errors = [];
        foreach ($ids as $pid) {
            $p = $policies[$pid];
            try {
                if (self::applies($p, $env)) {
                    if ($p->permit) {
                        $permits[] = $pid;
                    } else {
                        $forbids[] = $pid;
                    }
                }
            } catch (EvalError|Unsupported $err) {
                $errors[] = [$pid, $err->getMessage()];
            }
        }
        if ($forbids) {
            return ['decision' => 'deny', 'reasons' => $forbids, 'errors' => $errors];
        }
        if ($permits) {
            return ['decision' => 'allow', 'reasons' => $permits, 'errors' => $errors];
        }
        return ['decision' => 'deny', 'reasons' => [], 'errors' => $errors];
    }
}
