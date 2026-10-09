<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * A role a human holds and can lend to an agent for one task.
 *
 *   members   entities whose members hold the role (the user itself, or any
 *             group the user is in)
 *   cap       the ceiling: the most a token issued under this role can carry
 *   maxTtl    tokens under this role live at most this many seconds
 *   tasks     when set, the token must name a task matching one pattern
 *   agents    when set, only these agents may be started in this role
 *   bindings  free-form, for bridges; ignored by the engine
 */
final class Role
{
    private const KEYS = ['description', 'members', 'cap', 'max_ttl', 'tasks', 'agents', 'bindings'];

    public readonly string $name;
    /** @var list<Entity> */
    public readonly array $members;
    public readonly Cap $cap;
    public readonly int|BigInt|null $maxTtl;
    /** @var list<string>|null */
    public readonly ?array $tasks;
    /** @var list<string>|null */
    public readonly ?array $agents;
    public readonly JsonObject $bindings;

    /** @throws CedarValueError|EngineError for anything malformed: a misspelt key must never loosen a role */
    public function __construct(string $name, mixed $v)
    {
        if ($name === '' || !$v instanceof JsonObject) {
            throw new CedarValueError("role '$name' must be an object");
        }
        $unknown = array_values(array_diff($v->keys(), self::KEYS));
        if ($unknown) {
            sort($unknown, SORT_STRING);
            throw new CedarValueError("role '$name': unknown field(s): " . implode(', ', $unknown));
        }
        $this->name = $name;
        $members = $v->get('members');
        if (!is_array($members) || !$members) {
            throw new CedarValueError("role '$name': members must be a non-empty list of {type, id}");
        }
        $list = [];
        foreach ($members as $m) {
            if (!$m instanceof JsonObject || !Cedar::validType($m->get('type')) || !is_string($m->get('id'))) {
                throw new CedarValueError("role '$name': each member must be {type, id}");
            }
            $list[] = new Entity($m->get('type'), $m->get('id'));
        }
        $this->members = $list;
        if (!$v->has('cap')) {
            throw new CedarValueError("role '$name': cap is required");
        }
        $this->cap = Cap::fromJson($v->get('cap'));
        $this->cap->validate();
        $maxTtl = null;
        if ($v->has('max_ttl')) {
            $t = $v->get('max_ttl');
            if (!Num::isInt($t) || Num::cmp($t, 0) <= 0) {
                throw new CedarValueError("role '$name': max_ttl must be a positive integer");
            }
            $maxTtl = $t;
        }
        $this->maxTtl = $maxTtl;
        $this->tasks = $v->has('tasks') ? self::patternList($v->get('tasks'), "role '$name': tasks") : null;
        $this->agents = $v->has('agents') ? self::patternList($v->get('agents'), "role '$name': agents") : null;
        $b = $v->get('bindings');
        if ($v->has('bindings') && !$b instanceof JsonObject) {
            throw new CedarValueError("role '$name': bindings must be an object");
        }
        $this->bindings = $b instanceof JsonObject ? $b : new JsonObject();
    }

    private static function patternList(mixed $v, string $what): array
    {
        $ok = is_array($v) && $v !== [];
        foreach ($ok ? $v : [] as $x) {
            $ok = $ok && is_string($x) && $x !== '' && !str_contains(substr($x, 0, -1), '*');
        }
        if (!$ok) {
            throw new CedarValueError("$what must be a non-empty list of names, each with at most one trailing *");
        }
        return $v;
    }
}
