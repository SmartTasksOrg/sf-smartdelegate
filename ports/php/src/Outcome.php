<?php
declare(strict_types=1);

namespace SmartDelegate;

/** Internal: what the checks of one authorization request found. */
final class Outcome
{
    public bool $allow = false;
    public string $reason = '';
    public string $detail = '';
    /** @var list<string> */
    public array $policies = [];
    public ?Principal $principal = null;
    /** @var array<array-key,string>|null field => allow | deny | redact */
    public ?array $mask = null;
    public array $fieldAllow = [];
    public array $fieldDeny = [];
    public array $fieldRedact = [];
    /** @var list<JsonObject> */
    public array $rowFilter = [];
    /** @var list<array{string,int|BigInt,int|BigInt}> key, limit, window */
    public array $rate = [];
    public ?JsonObject $rateLimit = null;
    public ?JsonObject $approval = null;
    /** @var array{string,mixed}|null approval id, approver */
    public ?array $approved = null;
    /** @var array{string,int|BigInt}|null currency, amount */
    public ?array $spend = null;
    /** @var list<JsonObject> */
    public array $errors = [];
    /** @var list<JsonObject> */
    public array $trace = [];
}
