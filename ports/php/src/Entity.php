<?php
declare(strict_types=1);

namespace SmartDelegate;

/** An entity reference: (type, id). */
final class Entity
{
    /** Identity of the entity as an array key: unambiguous for any type and id, and never a numeric string. */
    public readonly string $key;

    public function __construct(public readonly string $type, public readonly string $id)
    {
        $this->key = strlen($type) . ':' . $type . $id;
    }

    public function __toString(): string
    {
        return $this->type . '::"' . $this->id . '"';
    }
}
