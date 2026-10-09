<?php
declare(strict_types=1);

namespace SmartDelegate;

/** Internal: a request that is denied (a normal result, not an error). */
final class Deny extends \Exception
{
    /** Claims of a token whose signature was good, so an expired or revoked token's denial can still be attributed. */
    public ?JsonObject $claims = null;

    public function __construct(public readonly string $reason, public readonly string $detail)
    {
        parent::__construct($reason . ': ' . $detail);
    }
}
