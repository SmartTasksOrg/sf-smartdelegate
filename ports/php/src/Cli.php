<?php
declare(strict_types=1);

namespace SmartDelegate;

/** The `smartdelegate-php` command line. Commands, flags and exit codes follow the reference CLI. */
final class Cli
{
    public const HELP = <<<'TXT'
smartdelegate-php - identity and access management for LLM agents (PHP port)

USAGE
  smartdelegate-php <command> [options]      JSON options accept @file, e.g. --cap @cap.json

SETUP
  info                                  version, policy version, mode, key id
  policy check                          load the bundle and report problems
  policy test                           run the bundle's tests/*.json
  bundle keygen <prefix>                write <prefix>.key and <prefix>.pub (Ed25519)
  bundle sign --key <file>              sign the bundle (writes bundle.sig.json)

TOKENS
  token issue --user U --agent A (--cap JSON | --role R [--cap JSON]) [--groups g1,g2]
              [--ttl S] [--tenant T] [--task X] [--id-token JWT] [--raw]
                                        --role: lend the agent a role the user holds; the
                                        token can never carry more than the role allows
  token exchange --token T --actor A [--cap JSON] [--ttl S] [--raw]
  token inspect --token T
  token revoke --id TOKEN_ID | --token T | --user U
                                        --user ends every token already issued for that user

DECISIONS
  authorize --token T --action A --resource path/id [--attrs JSON] [--context JSON]
            [--data JSON] [--strict] [--dry-run]      exit code 0 allow, 2 deny, 1 error
  explain   (same options)              show every check and every field decision
  approvals                             list held requests
  approve <approval_id> --by USER

AUDIT
  audit verify                          recompute the hash chain
  audit tail [-n N]

SERVERS
  serve [--listen 127.0.0.1:8181]       REST decision daemon

OTHER
  call <op> [--input JSON|@file|-]      any operation of spec/API.md, JSON in, JSON out
  conformance [<vectors dir> <bundle dir>]
                                        the policy-evaluation cases and the engine vectors;
                                        without arguments, those of this repository
  version

CONFIG
  --config FILE (or SMARTDELEGATE_CONFIG, or ./smartdelegate.json); --bundle DIR and --state DIR override it.
  --shadow logs would-be denials without enforcing them.

Not in this port: init, bundle compile (needs the Cedar toolchain: use the Rust port), bench,
http-proxy, mcp-proxy.

TXT;

    private const SWITCHES = ['raw', 'strict', 'dry-run', 'shadow', 'help'];

    /** @var list<string> */
    private array $pos = [];
    /** @var array<string,string> */
    private array $flags = [];

    /** @param list<string> $argv without the program name */
    public static function main(array $argv): int
    {
        try {
            return (new self($argv))->run();
        } catch (EngineError|\RuntimeException $e) {
            fwrite(STDERR, 'smartdelegate: ' . $e->getMessage() . "\n");
            return 1;
        } catch (\Throwable $e) {
            fwrite(STDERR, 'smartdelegate: internal error: ' . get_class($e) . ': ' . $e->getMessage() . "\n");
            return 1;
        }
    }

    private function __construct(array $argv)
    {
        $n = count($argv);
        for ($i = 0; $i < $n; $i++) {
            $x = (string) $argv[$i];
            if ($x === '--') {
                break;
            }
            $name = str_starts_with($x, '--') ? substr($x, 2) : (str_starts_with($x, '-') && strlen($x) === 2 ? substr($x, 1) : null);
            if ($name === null) {
                $this->pos[] = $x;
            } elseif (in_array($name, self::SWITCHES, true)) {
                $this->flags['=' . $name] = 'true';
            } elseif (str_contains($name, '=')) {
                [$k, $v] = explode('=', $name, 2);
                $this->flags['=' . $k] = $v;
            } else {
                $i++;
                if ($i >= $n) {
                    throw new \RuntimeException("--$name needs a value");
                }
                $this->flags['=' . $name] = (string) $argv[$i];
            }
        }
        if ($this->has('help')) {
            $this->pos = ['help'];
        }
    }

    private function flag(string $k): ?string
    {
        return $this->flags['=' . $k] ?? null;
    }

    /** The flag when it was given and is not empty. */
    private function val(string $k): ?string
    {
        $v = $this->flag($k);
        return $v === null || $v === '' ? null : $v;
    }

    private function has(string $k): bool
    {
        return isset($this->flags['=' . $k]);
    }

    private function need(string $k): string
    {
        if (!$this->has($k)) {
            throw new \RuntimeException("--$k is required");
        }
        return $this->flags['=' . $k];
    }

    /** A JSON value given inline or as @file. */
    private static function jsonArg(string $s): mixed
    {
        $text = $s;
        if (str_starts_with($s, '@')) {
            $file = substr($s, 1);
            $text = is_dir($file) ? false : @file_get_contents($file);
            if ($text === false) {
                throw new \RuntimeException("$file: cannot read the file");
            }
        }
        try {
            return Json::decodeBytes($text);
        } catch (JsonError $e) {
            throw new \RuntimeException('not valid JSON (' . $e->getMessage() . "): $s");
        }
    }

    private function config(): JsonObject
    {
        return Config::load($this->flag('config'), $this->flag('bundle'), $this->flag('state'), $this->has('shadow'));
    }

    private function engine(?JsonObject &$cfg = null): Engine
    {
        $cfg = $this->config();
        return new Engine($cfg);
    }

    private function callEngine(string $op, mixed $input): JsonObject
    {
        return new JsonObject($this->engine()->call($op, $input));
    }

    /** Print a result; exit code 0, 2 for a deny, 1 for an error. */
    private static function finish(JsonObject $v): int
    {
        echo Json::pretty($v, false), "\n";
        return $v->get('ok') !== true ? 1 : ($v->get('effect') === 'deny' ? 2 : 0);
    }

    /** @return array{JsonObject,string} input, operation */
    private function decisionInput(): array
    {
        $res = $this->need('resource');
        $slash = strpos($res, '/');
        $path = $slash === false ? $res : substr($res, 0, $slash);
        $rid = $slash === false ? '' : substr($res, $slash + 1);
        $resource = new JsonObject(['path' => $path, 'id' => $rid !== '' ? $rid : 'any']);
        $i = new JsonObject(['action' => $this->need('action'), 'resource' => $resource]);
        if ($this->val('token') !== null) {
            $i->set('token', $this->val('token'));
        }
        if ($this->val('attrs') !== null) {
            $resource->set('attrs', self::jsonArg($this->val('attrs')));
        }
        if ($this->val('context') !== null) {
            $i->set('context', self::jsonArg($this->val('context')));
        }
        if ($this->has('strict')) {
            $i->set('strict', true);
        }
        if ($this->has('dry-run')) {
            $i->set('dry_run', true);
        }
        if ($this->val('data') !== null) {
            $i->set('data', self::jsonArg($this->val('data')));
            return [$i, 'filter'];
        }
        return [$i, 'authorize'];
    }

    private function ttlOf(JsonObject $i): void
    {
        $ttl = $this->val('ttl');
        if ($ttl !== null) {
            if (preg_match('/^\s*[-+]?[0-9]+\s*$/', $ttl) !== 1) {
                throw new \RuntimeException('--ttl must be a number of seconds');
            }
            $i->set('ttl', Num::parse(ltrim(trim($ttl), '+')));
        }
    }

    private function tokenOut(JsonObject $v): int
    {
        if ($this->has('raw') && $v->get('ok') === true) {
            echo $v->get('token'), "\n";
            return 0;
        }
        return self::finish($v);
    }

    private static function report(array $results, string $label): int
    {
        foreach ($results['results'] as $r) {
            if (!$r['passed']) {
                echo 'FAIL ', Json::encode($r['name']), "\n", json_encode($r['failures'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
            }
        }
        echo "$label: {$results['total']} cases, {$results['failed']} failed\n";
        return $results['failed'] === 0 ? 0 : 1;
    }

    private function conformance(): int
    {
        $spec = dirname(__DIR__, 3) . '/spec/conformance';
        if (count($this->pos) === 2) {
            throw new \RuntimeException('usage: smartdelegate-php conformance [<vectors dir> <bundle dir>]');
        }
        $vectors = $this->pos[1] ?? "$spec/vectors";
        $bundle = $this->pos[2] ?? "$spec/bundle";
        $evalFile = count($this->pos) > 1 ? dirname(rtrim($vectors, '/')) . '/eval/cases.json' : "$spec/eval/cases.json";
        if (!is_dir($vectors) || !is_dir($bundle)) {
            throw new \RuntimeException("conformance: '$vectors' and '$bundle' must be directories");
        }
        $code = 0;
        if (is_file($evalFile)) {
            $code = self::report(Conformance::runEval($evalFile), 'eval');
        } else {
            echo "eval: skipped, no $evalFile\n";
        }
        $r = Conformance::runVectors($vectors, $bundle);
        foreach ($r['suites'] as $suite => $s) {
            echo "$suite: {$s['total']} cases, {$s['failed']} failed\n";
        }
        if ($r['total'] === 0) {
            throw new \RuntimeException("conformance: no cases found in $vectors");
        }
        echo "steps: {$r['steps']}\n";
        return max($code, self::report($r, 'conformance'));
    }

    private function run(): int
    {
        $cmd = $this->pos[0] ?? 'help';
        $sub = $this->pos[1] ?? '';
        if ($cmd === 'help' || $cmd === '-h') {
            echo self::HELP;
            return 0;
        }
        if ($cmd === 'version') {
            echo 'smartdelegate ', Engine::VERSION, " (php)\n";
            return 0;
        }
        if ($cmd === 'info') {
            return self::finish($this->callEngine('info', new JsonObject()));
        }
        if ($cmd === 'policy' && $sub === 'check') {
            $info = $this->callEngine('info', new JsonObject());
            echo "bundle loads: {$info['policies']} policies, version {$info['policy_version']}\n";
            return 0;
        }
        if ($cmd === 'policy' && $sub === 'test') {
            $r = Conformance::runBundleTests($this->config()->get('bundle_dir'));
            foreach ($r['results'] as $c) {
                echo $c['passed'] ? 'ok  ' : 'FAIL', ' ', is_string($c['name']) ? $c['name'] : Json::encode($c['name']), "\n";
                if (!$c['passed']) {
                    echo json_encode($c['failures'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
                }
            }
            echo "{$r['total']} tests, {$r['failed']} failed\n";
            return $r['failed'] === 0 ? 0 : 1;
        }
        if ($cmd === 'bundle' && $sub === 'keygen') {
            $prefix = $this->pos[2] ?? throw new \RuntimeException('usage: smartdelegate-php bundle keygen <prefix>');
            [$sk, $pk] = Bundle::keygen();
            $old = umask(0177);
            $ok = @file_put_contents($prefix . '.key', $sk) !== false;
            umask($old);
            if (!$ok || @file_put_contents($prefix . '.pub', $pk) === false) {
                throw new \RuntimeException("cannot write $prefix.key / $prefix.pub");
            }
            echo "wrote $prefix.key (keep secret) and $prefix.pub\nset \"bundle_public_key\": \"$pk\" in smartdelegate.json to require signed bundles\n";
            return 0;
        }
        if ($cmd === 'bundle' && $sub === 'sign') {
            $dir = $this->config()->get('bundle_dir');
            $keyFile = $this->need('key');
            $key = is_dir($keyFile) ? false : @file_get_contents($keyFile);
            if ($key === false) {
                throw new \RuntimeException("$keyFile: cannot read the key file");
            }
            $v = Bundle::sign($dir, $key);
            echo "signed bundle version {$v['version']} with key {$v['key_id']}\n";
            return 0;
        }
        if ($cmd === 'bundle' && $sub === 'compile') {
            throw new \RuntimeException('compiling .cedar to policies.json needs the Cedar toolchain: run `smartdelegate bundle compile` from the Rust port (ports/rust)');
        }
        if ($cmd === 'token' && $sub === 'issue') {
            $i = new JsonObject(['agent' => $this->need('agent')]);
            if ($this->val('cap') !== null) {
                $i->set('cap', self::jsonArg($this->val('cap')));
            } elseif ($this->val('role') === null) {
                throw new \RuntimeException('--cap JSON or --role NAME is required');
            }
            foreach (['user' => 'user', 'tenant' => 'tenant', 'task' => 'task', 'id_token' => 'id-token', 'role' => 'role'] as $k => $f) {
                if ($this->val($f) !== null) {
                    $i->set($k, $this->val($f));
                }
            }
            if ($this->has('groups')) {
                $i->set('groups', array_values(array_filter(explode(',', $this->flag('groups')), static fn (string $g): bool => $g !== '')));
            }
            $this->ttlOf($i);
            return $this->tokenOut($this->callEngine('issue_token', $i));
        }
        if ($cmd === 'token' && $sub === 'exchange') {
            $i = new JsonObject(['subject_token' => $this->need('token'), 'actor' => $this->need('actor')]);
            if ($this->val('cap') !== null) {
                $i->set('cap', self::jsonArg($this->val('cap')));
            }
            $this->ttlOf($i);
            return $this->tokenOut($this->callEngine('exchange_token', $i));
        }
        if ($cmd === 'token' && $sub === 'inspect') {
            return self::finish($this->callEngine('inspect_token', new JsonObject(['token' => $this->need('token')])));
        }
        if ($cmd === 'token' && $sub === 'revoke') {
            if ($this->val('user') !== null) {
                $i = new JsonObject(['user' => $this->val('user'), 'by' => 'cli']);
            } else {
                $i = $this->val('id') !== null
                    ? new JsonObject(['token_id' => $this->val('id'), 'by' => 'cli'])
                    : new JsonObject(['token' => $this->need('token'), 'by' => 'cli']);
            }
            return self::finish($this->callEngine('revoke', $i));
        }
        if ($cmd === 'call' && $sub !== '') {
            // any operation, input as JSON: the form other ports and scripts use
            $raw = $this->val('input') ?? '{}';
            if ($raw === '-') {
                try {
                    $input = Json::decodeBytes((string) stream_get_contents(STDIN));
                } catch (JsonError $e) {
                    throw new \RuntimeException('standard input is not valid JSON (' . $e->getMessage() . ')');
                }
            } else {
                $input = self::jsonArg($raw);
            }
            return self::finish($this->callEngine($sub, $input));
        }
        if ($cmd === 'authorize') {
            [$i, $op] = $this->decisionInput();
            return self::finish($this->callEngine($op, $i));
        }
        if ($cmd === 'explain') {
            return self::finish($this->callEngine('explain', $this->decisionInput()[0]));
        }
        if ($cmd === 'approvals') {
            return self::finish($this->callEngine('approvals', new JsonObject()));
        }
        if ($cmd === 'approve' && $sub !== '') {
            return self::finish($this->callEngine('approve', new JsonObject(['approval_id' => $sub, 'by' => $this->need('by')])));
        }
        if ($cmd === 'audit' && $sub === 'verify') {
            return self::finish($this->callEngine('audit_verify', new JsonObject()));
        }
        if ($cmd === 'audit' && $sub === 'tail') {
            $n = $this->val('n') ?? '20';
            if (preg_match('/^\s*[-+]?[0-9]+\s*$/', $n) !== 1) {
                throw new \RuntimeException('-n must be a number');
            }
            $r = $this->callEngine('audit_tail', new JsonObject(['n' => Num::parse(ltrim(trim($n), '+'))]));
            foreach (is_array($r->get('records')) ? $r->get('records') : [] as $rec) {
                echo Json::compact($rec, false), "\n";
            }
            return 0;
        }
        if ($cmd === 'serve') {
            $engine = $this->engine($cfg);
            $listen = $this->val('listen') ?? (Config::key($cfg, 'listen') !== '' ? Config::key($cfg, 'listen') : '127.0.0.1:8181');
            return Server::serve($engine, $listen, Config::key($cfg, 'admin_key'), Config::key($cfg, 'pep_key'));
        }
        if ($cmd === 'conformance') {
            return $this->conformance();
        }
        fwrite(STDERR, self::HELP);
        return 1;
    }
}
