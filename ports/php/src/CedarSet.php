<?php
declare(strict_types=1);

namespace SmartDelegate;

/** A Cedar set: unordered, no duplicates, any element types. */
final class CedarSet
{
    /** @var array<string,mixed> Cedar::key(value) => value */
    public array $items = [];

    /** @param iterable<mixed> $values Cedar values */
    public function __construct(iterable $values = [])
    {
        foreach ($values as $v) {
            $this->items[Cedar::key($v)] = $v;
        }
    }
}
