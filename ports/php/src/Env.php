<?php
declare(strict_types=1);

namespace SmartDelegate;

/** One authorization request as the evaluator sees it. */
final class Env
{
    /** @param array<array-key,mixed> $context a Cedar record */
    public function __construct(
        public readonly Entity $principal,
        public readonly Entity $action,
        public readonly Entity $resource,
        public readonly array $context,
        public readonly Store $store,
    ) {
    }
}
