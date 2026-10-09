<?php
declare(strict_types=1);

namespace SmartDelegate;

/** Entities: attributes and transitive ancestors. */
final class Store
{
    /** @var array<string,array> entity key => Cedar record */
    public array $attrs = [];
    /** @var array<string,list<Entity>> */
    public array $parents = [];
    /** @var array<string,array<string,true>> */
    private array $ancestors = [];

    /** @param mixed $entitiesJson the parsed entities.json: a list of {uid, attrs, parents} */
    public function __construct(mixed $entitiesJson = null)
    {
        if (!Json::truthy($entitiesJson)) {
            return;
        }
        if (!is_array($entitiesJson)) {
            throw new CedarValueError('entities must be a list');
        }
        foreach ($entitiesJson as $e) {
            $this->add($e);
        }
    }

    /** {type, id} or {"__entity": {type, id}} -> Entity */
    public static function uid(mixed $u): Entity
    {
        if ($u instanceof JsonObject && $u->has('__entity')) {
            $u = $u->get('__entity');
        }
        if (!$u instanceof JsonObject || !Cedar::validType($u->get('type')) || !is_string($u->get('id'))) {
            throw new CedarValueError('malformed entity uid');
        }
        return new Entity($u->get('type'), $u->get('id'));
    }

    public function add(mixed $e): Entity
    {
        if (!$e instanceof JsonObject) {
            throw new CedarValueError('an entity must be an object');
        }
        $uid = self::uid($e->get('uid'));
        if (array_key_exists($uid->key, $this->attrs)) {
            throw new CedarValueError("duplicate entity $uid");
        }
        $attrs = $e->get('attrs');
        if (!Json::truthy($attrs)) {
            $attrs = new JsonObject();
        }
        if (!$attrs instanceof JsonObject) {
            throw new CedarValueError("$uid: attrs must be an object");
        }
        $rec = [];
        foreach ($attrs->m as $k => $v) {
            $rec[$k] = Cedar::fromJson($v);
        }
        $parents = [];
        $ps = $e->get('parents');
        if (Json::truthy($ps)) {
            if (!is_array($ps)) {
                throw new CedarValueError("$uid: parents must be a list");
            }
            foreach ($ps as $p) {
                $parents[] = self::uid($p);
            }
        }
        $this->attrs[$uid->key] = $rec;
        $this->parents[$uid->key] = $parents;
        $this->ancestors = [];
        return $uid;
    }

    /** A store with request-scoped entities added. The base is not changed. */
    public function overlay(array $extra): self
    {
        $s = new self();
        $s->attrs = $this->attrs;
        $s->parents = $this->parents;
        foreach ($extra as $e) {
            $s->add($e);
        }
        return $s;
    }

    /**
     * A store in which `uid` has exactly these parents (and its stored
     * attributes, if any). Used for live group membership carried by a token.
     *
     * @param list<Entity> $parents
     */
    public function withParents(Entity $uid, array $parents): self
    {
        $s = new self();
        $s->attrs = $this->attrs;
        $s->parents = $this->parents;
        if (!array_key_exists($uid->key, $s->attrs)) {
            $s->attrs[$uid->key] = [];
        }
        $s->parents[$uid->key] = array_values($parents);
        return $s;
    }

    public function contains(Entity $uid): bool
    {
        return array_key_exists($uid->key, $this->attrs);
    }

    /** @return array<string,true> keys of every transitive parent */
    public function ancestors(Entity $uid): array
    {
        if (isset($this->ancestors[$uid->key])) {
            return $this->ancestors[$uid->key];
        }
        $seen = [];
        $stack = $this->parents[$uid->key] ?? [];
        while ($stack) {
            $p = array_pop($stack);
            if (!isset($seen[$p->key])) {
                $seen[$p->key] = true;
                foreach ($this->parents[$p->key] ?? [] as $pp) {
                    $stack[] = $pp;
                }
            }
        }
        return $this->ancestors[$uid->key] = $seen;
    }

    public function isIn(Entity $child, Entity $ancestor): bool
    {
        return $child->key === $ancestor->key || isset($this->ancestors($child)[$ancestor->key]);
    }
}
