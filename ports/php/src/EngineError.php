<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * A request that could not be processed. Becomes
 * {"ok": false, "error": {"code", "message", "rule"}}; never an allow.
 */
final class EngineError extends \Exception
{
    public function __construct(public readonly string $errorCode, public readonly string $detail)
    {
        parent::__construct($errorCode . ': ' . $detail);
    }

    /** `policy_forbid` -> `DELEGATE-POLICY-FORBID` */
    public static function ruleId(string $code): string
    {
        return 'DELEGATE-' . str_replace('_', '-', strtoupper($code));
    }

    public function toJson(): JsonObject
    {
        return new JsonObject(['ok' => false, 'error' => new JsonObject([
            'code' => $this->errorCode,
            'message' => mb_scrub($this->detail, 'UTF-8'),
            'rule' => self::ruleId($this->errorCode),
        ])]);
    }
}
