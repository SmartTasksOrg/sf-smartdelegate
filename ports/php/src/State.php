<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * Mutable engine state: revocations, approvals, spend ledger.
 *
 * One JSON file in the state directory. The engine holds the state-directory
 * lock for every operation and re-reads the file at the start of each one, so
 * processes sharing a directory see each other's changes on the next call.
 */
final class State
{
    public const KEYS = ['revoked', 'approvals', 'pending', 'ledger', 'limits', 'revoked_users'];

    private ?string $path;
    private string $raw = '';
    /**
     * {"revoked": {}, "approvals": {}, "pending": {}, "ledger": {}, "limits": {}, "revoked_users": {}}.
     * Every section is a JsonObject, so an empty one is written as {} (never
     * []): other ports read this file. `revoked_users` is never pruned.
     */
    public JsonObject $data;

    public function __construct(?string $dir)
    {
        $this->path = $dir !== null ? $dir . '/state.json' : null;
        $this->data = new JsonObject();
        foreach (self::KEYS as $k) {
            $this->data->set($k, new JsonObject());
        }
        $this->refresh();
    }

    public function section(string $name): JsonObject
    {
        return $this->data->m[$name];
    }

    public function refresh(): void
    {
        if ($this->path === null) {
            return;
        }
        clearstatcache(true, $this->path);
        if (!file_exists($this->path)) {
            return;
        }
        $text = @file_get_contents($this->path);
        if ($text === false) {
            throw new EngineError('state_io', error_get_last()['message'] ?? 'cannot read state.json');
        }
        if ($text === $this->raw) {
            return;
        }
        try {
            $data = Json::decode($text);
        } catch (JsonError) {
            $data = null;
        }
        $ok = $data instanceof JsonObject;
        foreach ($ok ? self::KEYS : [] as $k) {
            if (!$data->has($k)) {
                $data->set($k, new JsonObject());
            }
            $ok = $ok && $data->get($k) instanceof JsonObject;
        }
        if (!$ok) {
            // an unreadable state file must not silently drop revocations
            throw new EngineError('state_io', 'state.json is corrupt');
        }
        $this->data = $data;
        $this->raw = $text;
    }

    public function save(): void
    {
        if ($this->path === null) {
            return;
        }
        $text = Json::compact($this->data);
        $tmp = $this->path . '.tmp';
        if (@file_put_contents($tmp, $text) !== strlen($text) || !@rename($tmp, $this->path)) {
            throw new EngineError('state_io', error_get_last()['message'] ?? 'cannot write state.json');
        }
        $this->raw = $text;
    }

    public function prune(int|BigInt $now): void
    {
        $d = $this->data;
        $day = 86400;
        $keep = [];
        foreach ($d->m['revoked']->m as $k => $v) {
            if (Num::cmp(Num::add(Num::of($v), $day), $now) > 0) {
                $keep[$k] = $v;
            }
        }
        $d->set('revoked', new JsonObject($keep));
        $keep = [];
        foreach ($d->m['approvals']->m as $k => $v) {
            if (Num::cmp(Num::of(self::field($v, 'exp')), $now) > 0) {
                $keep[$k] = $v;
            }
        }
        $d->set('approvals', new JsonObject($keep));
        $keep = [];
        foreach ($d->m['pending']->m as $k => $v) {
            if (Num::cmp(Num::add(Num::of(self::field($v, 'requested_at')), $day), $now) > 0) {
                $keep[$k] = $v;
            }
        }
        $d->set('pending', new JsonObject($keep));
    }

    private static function field(mixed $v, string $key): mixed
    {
        if (!$v instanceof JsonObject || !$v->has($key)) {
            throw new \TypeError("state.json: an entry has no '$key'");
        }
        return $v->get($key);
    }
}
