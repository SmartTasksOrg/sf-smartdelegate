<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * Append-only, hash-chained decision log (JSON Lines).
 *
 * record.hash = sha256(prev_hash + canonical_json(record without "hash")).
 * Editing, deleting or reordering any line breaks every hash after it.
 * Truncating the tail is only detectable against a head hash kept elsewhere.
 */
final class Audit
{
    public const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

    public readonly string $path;
    private int|BigInt $seq = 0;
    private string $head = self::GENESIS;
    private int $len = 0;

    /**
     * Recompute the whole chain. Throws audit_broken naming the first bad line.
     *
     * @return JsonObject {"ok": true, "records": n, "head": hash}
     */
    public static function verify(string $path): JsonObject
    {
        $prev = self::GENESIS;
        $n = 0;
        $f = @fopen($path, 'rb');
        if ($f === false) {
            throw new EngineError('audit_io', 'cannot read audit log: ' . (error_get_last()['message'] ?? $path));
        }
        try {
            $lineno = 0;
            // a line ends at "\n" and nowhere else: CR, U+2028, U+2029 and U+0085 are data
            while (($line = fgets($f)) !== false) {
                $lineno++;
                if (!mb_check_encoding($line, 'UTF-8')) {
                    throw new EngineError('audit_broken', 'the audit log is not UTF-8');
                }
                if (Json::pyStrip($line) === '') {
                    continue;
                }
                try {
                    $rec = Json::decode($line);
                } catch (JsonError) {
                    $rec = null;
                }
                if (!$rec instanceof JsonObject) {
                    throw new EngineError('audit_broken', "line $lineno: not JSON");
                }
                $claimed = $rec->get('hash', '');
                $rec->remove('hash');
                if ($rec->get('prev') !== $prev) {
                    throw new EngineError('audit_broken', "line $lineno: prev hash does not match the line before");
                }
                if (!Json::pyEq($rec->get('seq'), $n + 1)) {
                    throw new EngineError('audit_broken', "line $lineno: sequence number is not " . ($n + 1));
                }
                if (hash('sha256', $prev . Canon::canon($rec)) !== $claimed) {
                    throw new EngineError('audit_broken', "line $lineno: content does not match its hash");
                }
                $prev = $claimed;
                $n++;
            }
        } finally {
            fclose($f);
        }
        return new JsonObject(['ok' => true, 'records' => $n, 'head' => $prev]);
    }

    /** The last `n` records that parse as JSON. */
    public static function tail(string $path, int|BigInt $n): array
    {
        clearstatcache(true, $path);
        if (!file_exists($path)) {
            return [];
        }
        $text = @file_get_contents($path);
        if ($text === false) {
            throw new EngineError('audit_io', 'cannot read audit log: ' . (error_get_last()['message'] ?? $path));
        }
        $lines = [];
        foreach (explode("\n", mb_scrub($text, 'UTF-8')) as $l) {   // "\n" only: U+2028 and friends are data
            if (Json::pyStrip($l) !== '') {
                $lines[] = $l;
            }
        }
        $count = count($lines);
        $take = Num::cmp($n, 0) <= 0 ? 0 : (Num::cmp($n, $count) >= 0 ? $count : (int) Num::str($n));
        $out = [];
        foreach ($take > 0 ? array_slice($lines, $count - $take) : [] as $l) {
            try {
                $out[] = Json::decode($l);
            } catch (JsonError) {
                // not JSON: skipped
            }
        }
        return $out;
    }

    public function __construct(string $path)
    {
        $this->path = $path;
        clearstatcache(true, $path);
        if (file_exists($path)) {
            $v = self::verify($path);
            $this->seq = $v->get('records');
            $this->head = $v->get('head');
            clearstatcache(true, $path);
            $this->len = (int) filesize($path);
        }
    }

    /**
     * Chain onto the last record if another process appended. The engine
     * holds the state-directory lock while this runs.
     */
    private function resync(): void
    {
        clearstatcache(true, $this->path);
        $size = file_exists($this->path) ? (int) @filesize($this->path) : 0;
        if ($size === $this->len) {
            return;
        }
        if ($size === 0) {
            throw new EngineError('audit_broken', 'the audit log was truncated while in use');
        }
        $f = is_dir($this->path) ? false : @fopen($this->path, 'rb');
        $text = false;
        if ($f !== false) {
            fseek($f, max(0, $size - (1 << 20)));
            $text = @stream_get_contents($f);
            fclose($f);
        }
        if ($text === false) {
            throw new EngineError('audit_io', 'cannot read audit log: ' . (error_get_last()['message'] ?? $this->path));
        }
        $last = null;
        foreach (explode("\n", mb_scrub($text, 'UTF-8')) as $l) {
            if (Json::pyStrip($l) !== '') {
                $last = $l;
            }
        }
        try {
            $rec = $last === null ? null : Json::decode($last);
        } catch (JsonError) {
            $rec = null;
        }
        $seq = $rec instanceof JsonObject ? $rec->get('seq') : null;
        $hash = $rec instanceof JsonObject ? $rec->get('hash') : null;
        if (!Num::isInt($seq) || !is_string($hash)) {
            throw new EngineError('audit_broken', 'the last audit record is unreadable');
        }
        $this->seq = $seq;
        $this->head = $hash;
        $this->len = $size;
    }

    /** Append one record; returns its hash. */
    public function append(JsonObject $record, int|BigInt $ts): string
    {
        $this->resync();
        $rec = $record->copy();
        $rec->remove('hash');
        $rec->set('seq', Num::add($this->seq, 1));
        $rec->set('ts', $ts);
        $rec->set('prev', $this->head);
        $h = hash('sha256', $this->head . Canon::canon($rec));
        $rec->set('hash', $h);
        $line = Canon::canon($rec) . "\n";
        $f = @fopen($this->path, 'ab');
        if ($f === false) {
            throw new EngineError('audit_io', 'cannot write audit log: ' . (error_get_last()['message'] ?? $this->path));
        }
        $written = @fwrite($f, $line);
        $flushed = @fflush($f);
        $stat = fstat($f);
        fclose($f);
        if ($written !== strlen($line) || !$flushed || $stat === false) {
            throw new EngineError('audit_io', 'cannot write audit log: short write');
        }
        $this->len = $stat['size'];
        $this->seq = Num::add($this->seq, 1);
        $this->head = $h;
        return $h;
    }
}
