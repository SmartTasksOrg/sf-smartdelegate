<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * A JSON object. PHP arrays cannot stand in for one: an empty array does not
 * say whether it is `{}` or `[]`, and `{"0": "a"}` would look like `["a"]`.
 * In this port a JSON object is always a JsonObject and a JSON list is always
 * a PHP list array.
 *
 * Keys are strings. PHP stores the key "123" as the integer 123; every
 * accessor here hands keys back as strings, and insertion order is kept.
 *
 *     $r['principal']['user']        // ArrayAccess
 *     foreach ($obj as $key => $v)   // $key is always a string
 *     json_encode($obj)              // {} stays {}
 */
final class JsonObject implements \ArrayAccess, \IteratorAggregate, \Countable, \JsonSerializable
{
    /** @var array<array-key,mixed> as PHP stores it; cast keys to string when reading them */
    public array $m;

    public function __construct(array $m = [])
    {
        $this->m = $m;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->m);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->m) ? $this->m[$key] : $default;
    }

    public function set(string $key, mixed $value): void
    {
        $this->m[$key] = $value;
    }

    public function remove(string $key): void
    {
        unset($this->m[$key]);
    }

    /** @return list<string> */
    public function keys(): array
    {
        return array_map('strval', array_keys($this->m));
    }

    public function isEmpty(): bool
    {
        return $this->m === [];
    }

    /** A shallow copy (Python's dict(x)). */
    public function copy(): self
    {
        return new self($this->m);
    }

    /** Native PHP data, recursively: objects become associative arrays. Lossy: {} and [] both become []. */
    public function toArray(): array
    {
        $out = [];
        foreach ($this->m as $k => $v) {
            $out[$k] = Json::toNative($v);
        }
        return $out;
    }

    public function count(): int
    {
        return count($this->m);
    }

    public function getIterator(): \Generator
    {
        foreach ($this->m as $k => $v) {
            yield (string) $k => $v;
        }
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->m[(string) $offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->m[(string) $offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        if ($offset === null) {
            throw new \LogicException('a JSON object needs a key');
        }
        $this->m[(string) $offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->m[(string) $offset]);
    }

    /** For json_encode(): always an object, never a list. Json::encode() is the exact writer. */
    public function jsonSerialize(): mixed
    {
        if ($this->m === []) {
            return new \stdClass();
        }
        return array_is_list($this->m) ? (object) $this->m : $this->m;
    }
}
