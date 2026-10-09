<?php
declare(strict_types=1);

namespace SmartDelegate;

/** One policy in Cedar's JSON form, checked against the portable subset when it is loaded. */
final class Policy
{
    public readonly string $id;
    public readonly bool $permit;
    public readonly JsonObject $principal;
    public readonly JsonObject $action;
    public readonly JsonObject $resource;
    /** @var list<JsonObject> */
    public readonly array $conditions;
    /** @var array<array-key,mixed> annotation name => value (a missing value is "") */
    public readonly array $annotations;

    /** @throws Unsupported */
    public function __construct(string $pid, mixed $est)
    {
        if (!$est instanceof JsonObject) {
            throw new Unsupported('malformed policy JSON (a policy must be an object)');
        }
        $effect = $est->get('effect');
        if ($effect !== 'permit' && $effect !== 'forbid') {
            throw new Unsupported('effect must be permit or forbid');
        }
        foreach (['principal', 'action', 'resource'] as $what) {
            Cedar::checkScope($est->get($what), $what);
        }
        $conds = $est->has('conditions') ? $est->get('conditions') : [];
        if (!is_array($conds)) {
            throw new Unsupported('malformed policy JSON (conditions must be a list)');
        }
        foreach ($conds as $c) {
            if (!$c instanceof JsonObject) {
                throw new Unsupported('malformed policy JSON (a condition must be an object)');
            }
            $kind = $c->get('kind');
            if ($kind !== 'when' && $kind !== 'unless') {
                throw new Unsupported('condition must be when or unless');
            }
            Cedar::checkExpr($c->get('body'));
        }
        $ann = $est->get('annotations');
        if (!Json::truthy($ann)) {
            $ann = new JsonObject();
        }
        if (!$ann instanceof JsonObject) {
            throw new Unsupported('malformed policy JSON (annotations must be an object)');
        }
        $annotations = [];
        foreach ($ann->m as $k => $v) {
            $annotations[$k] = $v === null ? '' : $v;
        }
        $this->id = $pid;
        $this->permit = $effect === 'permit';
        $this->principal = $est->get('principal');
        $this->action = $est->get('action');
        $this->resource = $est->get('resource');
        $this->conditions = array_values($conds);
        $this->annotations = $annotations;
    }
}
