<?php
/**
 * Test runner for the PHP port. No dependencies: `php test/run.php`.
 *
 *   1. policy evaluation      spec/conformance/eval/cases.json (95 cases)
 *   2. engine conformance     spec/conformance/vectors (78 cases, 327 steps), in-process
 *   3. conformance over REST  the same vectors through `smartdelegate-php serve` and Client, plus the HTTP rules
 *   4. interoperability       tokens, signed bundles, audit logs, one shared state directory, and a
 *                             step-by-step comparison of results with the Python reference
 *   5. JSON fidelity          {} vs [], int vs float, integers beyond 64 bits, canonical form, numeric keys
 *   6. front controller       public/index.php under `php -S`
 *   7. keys and failing closed key formats, token checks, ID token algorithms, corrupt files, the command line
 *
 * Section 4 needs python3 with the `cryptography` package and is skipped
 * (with a message) without it. Options: --only=1,5 to run some sections,
 * --verbose to list every check. Exit status 1 when anything fails.
 */
declare(strict_types=1);

require dirname(__DIR__) . '/src/autoload.php';

use SmartDelegate\Audit;
use SmartDelegate\BigInt;
use SmartDelegate\Bundle;
use SmartDelegate\Canon;
use SmartDelegate\Cap;
use SmartDelegate\Cedar;
use SmartDelegate\CedarValueError;
use SmartDelegate\Client;
use SmartDelegate\Conformance;
use SmartDelegate\Engine;
use SmartDelegate\EngineError;
use SmartDelegate\Entity;
use SmartDelegate\Env;
use SmartDelegate\Fields;
use SmartDelegate\Json;
use SmartDelegate\JsonError;
use SmartDelegate\JsonObject;
use SmartDelegate\Num;
use SmartDelegate\Policy;
use SmartDelegate\Server;
use SmartDelegate\Store;
use SmartDelegate\Tokens;

const T0 = 1700000000;

final class Run
{
    public static string $root;
    public static string $port;
    public static string $bin;
    public static string $bundle;
    public static string $vectors;
    public static string $tmp;
    public static bool $verbose = false;
    public static int $failed = 0;
    public static int $checks = 0;
    /** @var list<string> */
    public static array $summary = [];
    /** @var list<resource> */
    public static array $procs = [];
    private static int $sectionChecks = 0;
    private static int $sectionFailed = 0;

    public static function begin(): void
    {
        self::$sectionChecks = 0;
        self::$sectionFailed = 0;
    }

    public static function ok(bool $cond, string $what, string $detail = ''): bool
    {
        self::$checks++;
        self::$sectionChecks++;
        if (!$cond) {
            self::$failed++;
            self::$sectionFailed++;
            echo "  FAIL $what" . ($detail !== '' ? "\n       $detail" : '') . "\n";
            self::logFailure("FAIL $what" . ($detail !== '' ? " | $detail" : ''));
        } elseif (self::$verbose) {
            echo "  ok   $what\n";
        }
        return $cond;
    }

    /** Every failure goes to stderr, and to the file named by SMARTDELEGATE_TEST_LOG when that is set. */
    public static function logFailure(string $line): void
    {
        $line = '[smartdelegate-php test ' . gmdate('Y-m-d\TH:i:s\Z') . ' pid ' . getmypid() . '] ' . str_replace("\n", ' / ', $line) . "\n";
        fwrite(STDERR, $line);
        $log = getenv('SMARTDELEGATE_TEST_LOG');
        if (is_string($log) && $log !== '') {
            @file_put_contents($log, $line, FILE_APPEND | LOCK_EX);
        }
    }

    public static function eq(mixed $expected, mixed $actual, string $what): bool
    {
        return self::ok($expected === $actual, $what, 'expected ' . self::show($expected) . ', got ' . self::show($actual));
    }

    public static function show(mixed $v): string
    {
        try {
            return Json::encode(Json::fromNative($v), false);
        } catch (\Throwable) {
            return var_export($v, true);
        }
    }

    /** One summary line for the section. */
    public static function end(string $label, string $extra = ''): void
    {
        $line = sprintf('%s: %d checks, %d failed%s', $label, self::$sectionChecks, self::$sectionFailed, $extra !== '' ? " ($extra)" : '');
        self::$summary[] = $line;
        echo $line, "\n";
    }

    public static function note(string $line): void
    {
        self::$summary[] = $line;
        echo $line, "\n";
    }

    /** Poll until the condition holds; false when the (generous) deadline passes first. */
    public static function waitFor(callable $condition, float $seconds): bool
    {
        $deadline = microtime(true) + $seconds;
        while (!$condition()) {
            if (microtime(true) > $deadline) {
                return false;
            }
            usleep(10000);
        }
        return true;
    }

    public static function dir(string $name): string
    {
        $d = self::$tmp . '/' . $name . '-' . bin2hex(random_bytes(4));
        mkdir($d, 0700, true);
        return $d;
    }

    /** @return array{int,string,string} exit code, stdout, stderr */
    public static function exec(array $cmd, ?string $stdin = null, array $env = [], int $timeout = 300): array
    {
        $p = @proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, array_merge(getenv(), $env));
        if (!is_resource($p)) {
            return [127, '', 'cannot start ' . $cmd[0]];
        }
        if ($stdin !== null) {
            fwrite($pipes[0], $stdin);
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = $err = '';
        $deadline = microtime(true) + $timeout;
        while (true) {
            $r = array_filter([$pipes[1], $pipes[2]], static fn ($s): bool => !feof($s));
            if (!$r) {
                break;
            }
            if (microtime(true) > $deadline) {
                proc_terminate($p, 9);
                $err .= "\n[timed out after {$timeout}s]";
                break;
            }
            $w = $e = null;
            if (@stream_select($r, $w, $e, 1) > 0) {
                foreach ($r as $s) {
                    $chunk = (string) fread($s, 65536);
                    if ($s === $pipes[1]) {
                        $out .= $chunk;
                    } else {
                        $err .= $chunk;
                    }
                }
            }
        }
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($p), $out, $err];
    }

    public static function php(array $args, ?string $stdin = null, array $env = []): array
    {
        return self::exec([PHP_BINARY, self::$bin, ...$args], $stdin, $env);
    }

    /** The reference CLI: python3 -m sf_smartdelegate ... */
    public static function py(array $args, ?string $stdin = null, array $env = []): array
    {
        return self::exec(['python3', '-m', 'sf_smartdelegate', ...$args], $stdin, self::pyEnv() + $env);
    }

    public static function pyEnv(): array
    {
        $pp = getenv('PYTHONPATH');
        return ['PYTHONPATH' => self::$root . '/src' . ($pp ? PATH_SEPARATOR . $pp : ''), 'PYTHONDONTWRITEBYTECODE' => '1'];
    }

    public static function copyDir(string $from, string $to): void
    {
        mkdir($to, 0700, true);
        foreach (scandir($from) ?: [] as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            if (is_dir("$from/$name")) {
                self::copyDir("$from/$name", "$to/$name");
            } else {
                copy("$from/$name", "$to/$name");
            }
        }
    }

    public static function writeJson(string $file, mixed $v): string
    {
        file_put_contents($file, Json::encode(Json::fromNative($v)));
        return $file;
    }

    public static function confConfig(string $state, array $extra = []): array
    {
        return ['bundle_dir' => self::$bundle, 'state_dir' => $state, 'allow_test_clock' => true, 'max_depth' => 3] + $extra;
    }

    public static function cleanup(): void
    {
        foreach (self::$procs as $p) {
            if (is_resource($p)) {
                @proc_terminate($p, 9);
                @proc_close($p);
            }
        }
        self::$procs = [];
        if (isset(self::$tmp) && is_dir(self::$tmp)) {
            Conformance::removeDir(self::$tmp);
        }
    }
}

/** A server process on a free port: this port's daemon, the reference daemon, or `php -S`. */
final class Daemon
{
    public const ADMIN = 'admin-key-for-tests-0123456789';
    public const PEP = 'pep-key-for-tests-0123456789';

    public string $url = '';
    public string $dir;
    public string $config;
    /** @var resource|null */
    private $proc = null;
    /** @var resource|null */
    private $stderr = null;

    /** @param string $kind 'php' (bin/smartdelegate-php serve), 'python' (the reference) or 'builtin' (php -S + public/index.php) */
    public function __construct(mixed $suiteConfig = null, string $kind = 'php')
    {
        $this->dir = Run::dir('daemon');
        $cfg = Conformance::config(Run::$bundle, $this->dir . '/state', $suiteConfig instanceof JsonObject ? $suiteConfig : Json::fromNative($suiteConfig));
        $cfg->set('admin_key', self::ADMIN);
        $cfg->set('pep_key', self::PEP);
        $this->config = $this->dir . '/smartdelegate.json';
        file_put_contents($this->config, Json::encode($cfg));
        $env = getenv();
        unset($env['SMARTDELEGATE_ADMIN_KEY'], $env['SMARTDELEGATE_PEP_KEY']);
        if ($kind === 'builtin') {
            $s = stream_socket_server('tcp://127.0.0.1:0');
            $port = (int) substr(strrchr(stream_socket_get_name($s, false), ':'), 1);
            fclose($s);
            $cmd = [PHP_BINARY, '-S', "127.0.0.1:$port", Run::$port . '/public/index.php'];
            $env['SMARTDELEGATE_CONFIG'] = $this->config;
            unset($env['PHP_CLI_SERVER_WORKERS']);
        } elseif ($kind === 'python') {
            $cmd = ['python3', '-m', 'sf_smartdelegate', 'serve', '--config', $this->config, '--listen', '127.0.0.1:0'];
            $env = Run::pyEnv() + $env;
        } else {
            $cmd = [PHP_BINARY, Run::$bin, 'serve', '--config', $this->config, '--listen', '127.0.0.1:0'];
        }
        $this->proc = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['pipe', 'w']], $pipes, Run::$port, $env);
        if (!is_resource($this->proc)) {
            throw new \RuntimeException('cannot start ' . implode(' ', $cmd));
        }
        Run::$procs[] = $this->proc;
        $this->stderr = $pipes[2];
        if ($kind === 'builtin') {
            $this->url = "http://127.0.0.1:$port";
            $deadline = microtime(true) + 120;
            while (microtime(true) < $deadline) {
                $c = @stream_socket_client("tcp://127.0.0.1:$port", $en, $es, 0.2);
                if ($c !== false) {
                    fclose($c);
                    stream_set_blocking($this->stderr, false);
                    return;
                }
                usleep(20000);
            }
            throw new \RuntimeException('php -S did not start');
        }
        $r = [$this->stderr];
        $w = $e = null;
        $line = stream_select($r, $w, $e, 120) > 0 ? (string) fgets($this->stderr) : '';
        if (preg_match('{http://(\S+)}', $line, $m) !== 1) {
            throw new \RuntimeException("the daemon did not start: $line");
        }
        $this->url = 'http://' . $m[1];
        Run::ok(str_starts_with($line, 'smartdelegate daemon listening on http://127.0.0.1:'), 'startup line on stderr', $line);
        stream_set_blocking($this->stderr, false);
    }

    public function client(): Client
    {
        return new Client($this->url, self::PEP, self::ADMIN, 120.0);
    }

    /**
     * A raw HTTP exchange.
     *
     * @return array{int,string} status, body
     */
    public function http(string $method, string $target, array $headers = [], ?string $body = null, ?string $rawRequest = null): array
    {
        $hostPort = substr($this->url, 7);
        $s = @stream_socket_client("tcp://$hostPort", $en, $es, 60);
        if ($s === false) {
            return [0, "connect: $es"];
        }
        stream_set_timeout($s, 120);
        if ($rawRequest === null) {
            $rawRequest = "$method $target HTTP/1.1\r\nHost: $hostPort\r\nConnection: close\r\n";
            foreach ($headers as $k => $v) {
                $rawRequest .= "$k: $v\r\n";
            }
            if ($body !== null && !isset($headers['Content-Length'])) {
                $rawRequest .= 'Content-Length: ' . strlen($body) . "\r\n";
            }
            $rawRequest .= "\r\n" . ($body ?? '');
        }
        fwrite($s, $rawRequest);
        $resp = (string) stream_get_contents($s);
        fclose($s);
        $status = preg_match('{^HTTP/\S+ (\d{3})}', $resp, $m) === 1 ? (int) $m[1] : 0;
        $i = strpos($resp, "\r\n\r\n");
        return [$status, $i === false ? '' : substr($resp, $i + 4)];
    }

    public function close(): void
    {
        if (is_resource($this->proc)) {
            proc_terminate($this->proc, 9);
            if (is_resource($this->stderr)) {
                fclose($this->stderr);
            }
            proc_close($this->proc);
        }
        $this->proc = null;
        Conformance::removeDir($this->dir);
    }
}

/** The reference engine in one Python process: a line `[op, payload]` in, the result as a line out. */
final class Reference
{
    private const DRIVER = <<<'PY'
import json, sys
from smartdelegate import Engine, canon
mode = sys.argv[1]
engine = Engine(json.loads(sys.argv[2])) if mode == "engine" else None
for line in sys.stdin:
    req = json.loads(line)
    if mode == "engine":
        out = json.dumps(engine.call(req[0], req[1]))
    else:
        out = json.dumps(canon.canon(req))
    sys.stdout.write(out + "\n")
    sys.stdout.flush()
PY;

    /** @var resource */
    private $proc;
    private array $pipes = [];

    public function __construct(string $mode, mixed $config = null)
    {
        $this->proc = proc_open(['python3', '-c', self::DRIVER, $mode, Json::encode(Json::fromNative($config ?? new JsonObject()))],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', Run::$tmp . '/python-driver.err', 'a']], $this->pipes, null, array_merge(getenv(), Run::pyEnv()));
        Run::$procs[] = $this->proc;
    }

    /** One line in, one line out (raw text). */
    public function ask(string $line): string
    {
        fwrite($this->pipes[0], $line . "\n");
        fflush($this->pipes[0]);
        $r = [$this->pipes[1]];
        $w = $e = null;
        if (stream_select($r, $w, $e, 180) < 1) {
            throw new \RuntimeException('the Python reference did not answer: ' . @file_get_contents(Run::$tmp . '/python-driver.err'));
        }
        $out = fgets($this->pipes[1]);
        if ($out === false) {
            throw new \RuntimeException('the Python reference stopped: ' . @file_get_contents(Run::$tmp . '/python-driver.err'));
        }
        return rtrim($out, "\n");
    }

    public function close(): void
    {
        fclose($this->pipes[0]);
        fclose($this->pipes[1]);
        proc_close($this->proc);
    }
}

// ---- 1. policy evaluation ---------------------------------------------------------

function section_eval(): void
{
    Run::begin();
    $r = Conformance::runEval(Run::$root . '/spec/conformance/eval/cases.json');
    foreach ($r['results'] as $c) {
        Run::ok($c['passed'], 'eval: ' . Run::show($c['name']), $c['passed'] ? '' : $c['failures'][0]['mismatch']);
    }
    Run::ok($r['total'] > 0, 'the eval file has cases');
    Run::end('1. policy evaluation', "{$r['total']} cases, {$r['failed']} failed");
}

// ---- 2. engine conformance, in-process ------------------------------------------------

function section_vectors(): void
{
    Run::begin();
    $r = Conformance::runVectors(Run::$vectors, Run::$bundle);
    foreach ($r['results'] as $c) {
        Run::ok($c['passed'], "{$c['suite']}: " . Run::show($c['name']), $c['passed'] ? '' : json_encode($c['failures']));
    }
    Run::ok($r['total'] > 0, 'the vectors directory has cases');
    // the runner itself must be able to fail
    $probe = Json::decode('{"name":"probe","steps":[{"op":"nonsense","input":{},"expect":{"ok":true}}]}');
    $e = new Engine(['bundle_dir' => Run::$bundle]);
    Run::ok(Conformance::runCase([$e, 'call'], $probe)['passed'] === false, 'the runner reports a mismatch as a failure');
    Run::ok(Conformance::subset(Json::decode('{"a":null}'), Json::decode('{}')) === null, 'expected null matches a missing key');
    Run::ok(Conformance::subset(Json::decode('{"a":1}'), Json::decode('{"a":true}')) !== null, 'expected 1 does not match true');
    Run::ok(Conformance::subset(Json::decode('{"a":[]}'), Json::decode('{"a":{}}')) !== null, 'expected [] does not match {}');
    $e->close();
    Run::end('2. engine conformance in-process', "{$r['total']} cases, {$r['steps']} steps, {$r['failed']} failed");
}

// ---- 3. conformance over REST -------------------------------------------------------

/** @return list<array{string,JsonObject,mixed}> suite, case, suite config */
function all_cases(): array
{
    $out = [];
    foreach (Conformance::jsonFiles(Run::$vectors) as $file) {
        $doc = Conformance::readJson($file);
        foreach ($doc->get('cases') as $case) {
            $out[] = [basename($file, '.json'), $case, $doc->get('config')];
        }
    }
    return $out;
}

/** The HTTP rules of the daemon: [name, method, target, headers, body, expected status, expected error code]. */
function http_probes(): array
{
    $admin = ['Authorization' => 'Bearer ' . Daemon::ADMIN];
    $pep = ['Authorization' => 'Bearer ' . Daemon::PEP];
    $issue = '{"user":"alice","agent":"support-bot","cap":{"actions":["read"],"resources":["crm.customer/*"]},"now":' . T0 . '}';
    return [
        ['healthz needs no key', 'GET', '/healthz', [], null, 200, null],
        ['healthz by POST', 'POST', '/healthz', [], '', 200, null],
        ['info without a key', 'GET', '/v1/info', [], null, 401, 'unauthorized'],
        ['info with a wrong key', 'GET', '/v1/info', ['Authorization' => 'Bearer nope-nope-nope-nope'], null, 401, 'unauthorized'],
        ['info with the pep key', 'GET', '/v1/info', $pep, null, 200, null],
        ['info with the admin key', 'GET', '/v1/info', $admin, null, 200, null],
        ['info ignores a query string', 'GET', '/v1/info?x=1', $pep, null, 200, null],
        ['the scheme is case-sensitive', 'GET', '/v1/info', ['Authorization' => 'bearer ' . Daemon::PEP], null, 401, 'unauthorized'],
        ['spaces around the key are ignored', 'GET', '/v1/info', ['Authorization' => 'Bearer   ' . Daemon::PEP . '  '], null, 200, null],
        ['a key prefix is not the key', 'GET', '/v1/info', ['Authorization' => 'Bearer ' . substr(Daemon::PEP, 0, -1)], null, 401, 'unauthorized'],
        ['admin route with the pep key', 'GET', '/v1/admin/approvals', $pep, null, 401, 'unauthorized'],
        ['admin route with the admin key', 'GET', '/v1/admin/approvals', $admin, null, 200, null],
        ['root token without a key', 'POST', '/v1/token', [], $issue, 401, 'unauthorized'],
        ['root token with the pep key', 'POST', '/v1/token', $pep, $issue, 401, 'unauthorized'],
        ['root token with the admin key', 'POST', '/v1/token', $admin, $issue, 200, null],
        ['exchange needs no key', 'POST', '/v1/token', [], '{"subject_token":"x.y.z","actor":"refund-helper"}', 400, 'token_invalid'],
        ['an ID token needs no key', 'POST', '/v1/token', [], '{"id_token":"x.y.z","agent":"support-bot","user":"alice","cap":{}}', 400, 'no_idp'],
        ['bad JSON is refused before the key is checked', 'POST', '/v1/authorize', [], '{"action":', 400, 'invalid_input'],
        ['a body that is not an object', 'POST', '/v1/authorize', $pep, '[1]', 400, 'invalid_input'],
        ['an empty body is an empty object', 'POST', '/v1/authorize', $pep, '', 400, 'invalid_input'],
        ['white space only is an empty object', 'POST', '/v1/admin/reload', $admin, " \r\n\t", 200, null],
        ['authorize without a key', 'POST', '/v1/authorize', [], '{}', 401, 'unauthorized'],
        ['unknown path', 'POST', '/nope', $admin, '{}', 404, 'not_found'],
        ['a route with the wrong method', 'GET', '/v1/authorize', $admin, null, 404, 'not_found'],
        ['the path is not normalised', 'GET', '/v1/info/', $admin, null, 404, 'not_found'],
        ['bad Content-Length', 'POST', '/v1/authorize', $pep + ['Content-Length' => 'abc'], '', 400, 'invalid_input'],
        ['a body over 8 MiB is refused unread', 'POST', '/v1/authorize', $pep + ['Content-Length' => (string) (Server::MAX_BODY + 1)], '', 400, 'invalid_input'],
        ['audit tail', 'GET', '/v1/admin/audit/tail?n=1', $admin, null, 200, null],
        ['audit tail with a bad n', 'GET', '/v1/admin/audit/tail?n=x&m=2', $admin, null, 200, null],
        ['audit verify', 'GET', '/v1/admin/audit/verify', $admin, null, 200, null],
        ['unsupported method', 'PUT', '/v1/info', $admin, null, 501, null],
        ['a denied decision is still 200', 'POST', '/v1/authorize', $pep, '{"token":"x.y.z","action":"read","resource":{"path":"crm.customer"}}', 200, null],
        ['NaN is read as Python reads it', 'POST', '/v1/authorize', $pep, '{"token":"x.y.z","action":"read","resource":{"path":"crm.customer"},"context":{"x":NaN}}', 200, null],
    ];
}

/** @return array<string,array{int,mixed,mixed}> name => status, ok, error code */
function run_probes(Daemon $d, array $skip = []): array
{
    $out = [];
    foreach (http_probes() as [$name, $method, $target, $headers, $body]) {
        if (in_array($name, $skip, true)) {
            continue;
        }
        [$status, $text] = $d->http($method, $target, $headers, $body);
        try {
            $v = Json::decode($text);
        } catch (JsonError) {
            $v = null;
        }
        $out[$name] = [$status, $v instanceof JsonObject ? $v->get('ok') : null, $v instanceof JsonObject && $v->get('error') instanceof JsonObject ? $v['error']['code'] : null];
    }
    return $out;
}

function section_rest(): void
{
    Run::begin();
    $n = $failed = 0;
    foreach (all_cases() as [$suite, $case, $config]) {
        $d = new Daemon($config);
        try {
            $r = Conformance::runCase([$d->client(), 'call'], $case);
        } finally {
            $d->close();
        }
        $n++;
        $failed += $r['passed'] ? 0 : 1;
        Run::ok($r['passed'], "$suite over REST: " . Run::show($r['name']), $r['passed'] ? '' : json_encode($r['failures']));
    }

    $d = new Daemon();
    try {
        $got = run_probes($d);
        foreach (http_probes() as [$name, , , , , $status, $code]) {
            Run::ok($got[$name][0] === $status && ($status === 501 || $got[$name][2] === $code), "http: $name",
                "expected $status " . Run::show($code) . ', got ' . Run::show($got[$name]));
        }
        // the 8 MiB limit is on the declared length, and the body itself may be large
        $big = '{"token":"x.y.z","action":"read","resource":{"path":"crm.customer"},"pad":"' . str_repeat('a', 6 * 1024 * 1024) . '"}';
        [$status, $text] = $d->http('POST', '/v1/authorize', ['Authorization' => 'Bearer ' . Daemon::PEP], $big);
        Run::ok($status === 200 && str_contains($text, '"token_invalid"'), 'http: a 6 MiB body is read and answered', "status $status");
        // an ID token request has `user` removed before the engine sees it; that is visible in the error order only
        // through a configured provider, which the 08_oidc vectors cover. Here: two requests on one daemon in a row.
        $c = $d->client();
        $t = $c->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => ['actions' => ['read'], 'resources' => ['crm.customer/*']]]);
        Run::ok(($t['ok'] ?? null) === true && ($t['cap']['budget'] ?? null) instanceof JsonObject, 'client: nested objects come back as JsonObject');
        $a = $c->call('authorize', ['token' => $t['token'] ?? '', 'action' => 'read', 'resource' => ['path' => 'crm.customer', 'id' => 'c-1']]);
        Run::eq('allow', $a['effect'] ?? null, 'client: authorize over REST');
        Run::eq('unknown_op', $c->call('nonsense', [])['error']['code'] ?? null, 'client: unknown operation');
        // slow clients do not block others: an unfinished request is open while another one is served
        $slow = stream_socket_client('tcp://' . substr($d->url, 7), $en, $es, 5);
        fwrite($slow, "POST /v1/authorize HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\n{\"partial\":");
        [$status] = $d->http('GET', '/healthz');
        Run::eq(200, $status, 'http: a stalled request does not block the next client');
        fclose($slow);
    } finally {
        $d->close();
    }
    // identity comes from the ID token alone: over REST `user` is dropped before the engine sees it
    $oidc = Conformance::readJson(Run::$vectors . '/08_oidc.json')->get('config');
    $idt = Conformance::readJson(Run::$root . '/spec/conformance/oidc/id_tokens.json')['alice'];
    $ask = ['id_token' => $idt, 'user' => 'bob', 'agent' => 'support-bot', 'cap' => ['actions' => ['read'], 'resources' => ['crm.customer/*']], 'now' => T0];
    $d = new Daemon($oidc);
    try {
        [$status, $text] = $d->http('POST', '/v1/token', [], Json::encode(Json::fromNative($ask)));
        Run::ok($status === 200 && Json::decode($text)['user'] === 'alice', 'http: an ID token needs no key, and a `user` beside it is ignored', "$status $text");
        [$status, $text] = $d->http('POST', '/v1/token', [], Json::encode(Json::fromNative(['id_token' => 'x.y.z'] + $ask)));
        Run::ok($status === 400 && Json::decode($text)['error']['code'] === 'id_token_invalid', 'http: a bad ID token is a 400', "$status $text");
        Run::eq('alice', $d->client()->call('issue_token', $ask)['user'] ?? null, 'client: issue_token with an ID token');
    } finally {
        $d->close();
    }
    $direct = new Engine(Conformance::config(Run::$bundle, Run::dir('oidc-direct'), $oidc));
    Run::eq('id_token_invalid', $direct->call('issue_token', $ask)['error']['code'] ?? null, 'in-process, the same request is refused: the ID token belongs to a different user');
    $direct->close();

    $unreachable = false;
    try {
        (new Client('http://127.0.0.1:1', 'k', 'k', 2.0))->call('info', []);
    } catch (EngineError $e) {
        $unreachable = $e->errorCode === 'daemon_unreachable';
    }
    Run::ok($unreachable, 'client: an unreachable daemon is an error, never an allow');
    [$code, , $err] = Run::php(['serve', '--bundle', Run::$bundle, '--listen', '127.0.0.1:0'], null, ['SMARTDELEGATE_ADMIN_KEY' => 'short', 'SMARTDELEGATE_PEP_KEY' => '']);
    Run::ok($code === 1 && str_contains($err, 'serve needs admin_key and pep_key'), 'serve refuses to start without keys', $err);
    Run::end('3. conformance over REST (own daemon, own client)', "$n cases, $failed failed");
}

// ---- 4. interoperability with the Python reference ----------------------------------------

function python_available(): ?string
{
    [$code, , $err] = Run::exec(['python3', '-c', 'import cryptography, smartdelegate'], null, Run::pyEnv());
    if ($code === 127) {
        return 'python3 is not installed';
    }
    return $code === 0 ? null : 'python3 cannot import the reference (is the `cryptography` package installed?): ' . trim(substr($err, -200));
}

/** Result text -> comparable text: values that legitimately differ between two engines are blanked. */
function masked(mixed $v, bool $text): string
{
    $volatile = ['token', 'token_id', 'jti', 'decision_id', 'key_id', 'public_key', 'implementation', 'hash', 'prev',
        'request_hash', 'revoked', 'head'];
    if ($text) {
        array_push($volatile, 'message', 'detail');
    }
    $walk = static function (mixed $v) use (&$walk, $volatile): mixed {
        if ($v instanceof JsonObject) {
            $out = [];
            foreach ($v->m as $k => $x) {
                $k = (string) $k;
                if (in_array($k, $volatile, true) && $x !== null) {
                    $out[$k] = '<' . Json::pyType($x) . '>';
                } elseif (in_array($k, ['anc', 'ancestors'], true) && is_array($x)) {
                    $out[$k] = '<' . count($x) . ' ids>';
                } elseif (in_array($k, ['ledger', 'limits', 'lim'], true) && $x instanceof JsonObject) {
                    $out[$k] = array_values(array_map($walk, $x->m));
                } else {
                    $out[$k] = $walk($x);
                }
            }
            return new JsonObject($out);
        }
        return is_array($v) ? array_map($walk, $v) : $v;
    };
    return Canon::canon($walk($v));
}

/**
 * Requests whose results must be the same in both engines. `"$name"` is
 * replaced by a value saved from an earlier result of the same engine.
 *
 * @return list<array{0:string,1:string,2?:array<string,string>}> op, input (JSON text), save
 */
function differential_steps(): array
{
    $t = T0;
    $cap = '{"actions":["read","create","update"],"resources":["crm.customer/*","billing.refund/*"],"budget":{"EUR":20000}}';
    $c1 = '"resource":{"path":"crm.customer","id":"c-1"}';
    $refund = '"action":"create","resource":{"path":"billing.refund","id":"r-1"}';
    $rec = '{"id":"c-1","name":"Ann","region":"EU","tier":1,"ssn":"s","notes":"n","123":"x","08":8,"card":{"last4":"1","number":"4111","x":1.0},'
        . '"addresses":[{"geo":1,"zip":1e16},[],{},"s",7],"big":123456789012345678901234567890,"\uffff":1,"\ud83d\ude00":2,"f":[0.1,-0.0,1.5e-7,1e22,100.0],"n":null,"e":{},"l":[]}';
    $ob = '{"fields":{"allow":["a","1","o"],"deny":["b"],"redact":["c"]},"row_filter":[{"column":"n","op":"eq","value":1}]}';
    return [
        // -- payloads that are not objects, unknown operations
        ['info', '{}'], ['info', '[]'], ['info', '"x"'], ['info', '5'], ['info', 'null'], ['info', '{"extra":[{}]}'],
        ['nonsense', '{}'], ['', '{}'],
        // -- capabilities: {} vs [], integers vs floats, integers beyond 64 bits
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"now":' . $t . '}', ['t' => 'token', 'tid' => 'token_id']],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["read"],"resources":["crm.customer/*"],"budget":{}},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["read"],"resources":["crm.customer/*"],"budget":[]},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["read"],"resources":["crm.customer/*"],"budget":0},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["read"],"resources":["crm.customer/*"],"budget":[1]},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"budget":{"EUR":1.0}},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"budget":{"EUR":true}},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"budget":{"EUR":-1}},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"budget":{"EUR":123456789012345678901234567890}},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"budget":{"EUR":-123456789012345678901234567890}},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"budget":{"EUR":9223372036854775807,"123":5,"\u00e9":0}},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"budget":{"EUR":9223372036854775808}},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"budget":"x"},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":[],"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":null,"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":"read"},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":[1]},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":{}},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["re*d"]},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":[""]},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["read"],"zzz":1,"aaa":2},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"ttl":1.0,"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"ttl":true,"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"ttl":"5","now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"ttl":5,"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"ttl":0,"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"ttl":99999999999999999999999,"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"ttl":-99999999999999999999999,"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"tenant":"","task":5,"now":' . $t . '}'],
        ['issue_token', '{"user":"","agent":"support-bot","cap":' . $cap . ',"now":' . $t . '}'],
        ['issue_token', '{"user":5,"agent":"support-bot","cap":' . $cap . ',"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"no-such","cap":' . $cap . ',"now":' . $t . '}'],
        ['issue_token', '{"user":"al\u00e9\ud83d\ude00\u0001","agent":"support-bot","cap":' . $cap . ',"now":' . $t . '}'],
        // -- a clock beyond 64 bits: Python integers are unbounded, so the token carries the number exactly
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"now":99999999999999999999999}', ['far' => 'token']],
        ['inspect_token', '{"token":"$far","now":99999999999999999999999}'],
        ['inspect_token', '{"token":"$far","now":100000000000000000000899}'],
        ['inspect_token', '{"token":"$far","now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"now":9223372036854775807}', ['edge' => 'token']],
        ['inspect_token', '{"token":"$edge","now":9223372036854775807}'],
        ['authorize', '{"token":"$edge","action":"read",' . $c1 . ',"now":9223372036854775807}'],
        // -- roles and live membership
        ['issue_token', '{"user":"dave","agent":"support-bot","role":"support-agent","groups":["support"],"now":' . $t . '}', ['d' => 'token']],
        ['issue_token', '{"user":"dave","agent":"support-bot","role":"support-agent","groups":"support","now":' . $t . '}'],
        ['issue_token', '{"user":"dave","agent":"support-bot","role":"support-agent","groups":[{"type":"Group","id":"support"},"support","nope",{"type":"Group","id":"compliance"}],"now":' . $t . '}', ['d2' => 'token']],
        ['inspect_token', '{"token":"$d2","now":' . $t . '}'],
        ['issue_token', '{"user":"dave","agent":"support-bot","role":"support-agent","groups":[1],"now":' . $t . '}'],
        ['issue_token', '{"user":"dave","agent":"support-bot","role":"support-agent","groups":{},"now":' . $t . '}'],
        ['issue_token', '{"user":"dave","agent":"support-bot","role":"support-agent","groups":{"type":"Group","id":"support"},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","role":"support-agent","groups":[],"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","role":"support-agent","now":' . $t . '}', ['r' => 'token']],
        ['issue_token', '{"user":"alice","agent":"support-bot","role":"support-agent","cap":{"actions":["read"],"resources":["crm.customer/c-1"],"deny_labels":["pii","pii"],"budget":{"EUR":10001}},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","role":"support-agent","cap":{"actions":["read"],"resources":["crm.customer/c-1"],"deny_labels":["zz","pii","pii"],"deny_fields":["b","a"]},"ttl":3600,"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","role":"nope","now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","role":5,"now":' . $t . '}'],
        ['inspect_token', '{"token":"$d","now":' . $t . '}'],
        ['authorize', '{"token":"$d","action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$d","actor":"refund-helper","ttl":300,"role":"supervisor","now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$d","actor":"refund-helper","ttl":300,"now":' . $t . '}', ['dc' => 'token']],
        ['inspect_token', '{"token":"$dc","now":' . $t . '}'],
        // -- delegation
        ['exchange_token', '{"subject_token":"$t","actor":"refund-helper","cap":{"actions":["read"],"resources":["crm.customer/c-1"],"deny_labels":["pii"],"budget":{"EUR":5000}},"ttl":300,"now":' . $t . '}', ['c' => 'token']],
        ['exchange_token', '{"subject_token":"$t","actor":"refund-helper","cap":{"actions":["read"],"resources":["crm.customer/c-1"],"budget":{"EUR":20001}},"ttl":300,"now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$t","actor":"refund-helper","cap":{"actions":["read"],"resources":["crm.customer/c-1"],"budget":{"EUR":99999999999999999999}},"ttl":300,"now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$t","actor":"refund-helper","cap":{"actions":["read"],"resources":["crm.customer/c-1"],"budget":{"USD":1}},"ttl":300,"now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$t","actor":"refund-helper","cap":{"actions":["*"],"resources":["crm.customer/c-1"]},"ttl":300,"now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$t","actor":"refund-helper","cap":{"actions":["read"],"resources":["crm.customer/c-1"],"budget":[]},"ttl":300,"now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$t","actor":"refund-helper","ttl":601,"now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$t","actor":"refund-helper","ttl":99999999999999999999,"now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$t","actor":"rogue-bot","ttl":60,"now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$t","ttl":60,"now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"garbage","actor":"refund-helper","now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"a.b.c","actor":"refund-helper","now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$t","actor":"refund-helper","now":' . ($t + 900) . '}'],
        ['inspect_token', '{"token":"$c","now":' . $t . '}'],
        ['inspect_token', '{"token":"$t","now":' . ($t - 61) . '}'],
        ['inspect_token', '{"token":"$t","now":' . ($t - 60) . '}'],
        ['inspect_token', '{"token":"$t.","now":' . $t . '}'],
        ['inspect_token', '{"token":"","now":' . $t . '}'],
        ['inspect_token', '{"token":["x"],"now":' . $t . '}'],
        // -- decisions: the shape of the request
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":null,"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":[],"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":[{"a":1}],"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":"x","now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":0,"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{"x":1.0},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{"x":[{"y":1.5}]},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{"x":null},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{"x":9223372036854775807,"y":-9223372036854775808},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{"x":9223372036854775808},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{"x":-9223372036854775809},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{"iam":{}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{"x":{"__extn":{"fn":"ip","arg":"1.2.3.4"}}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{"x":{"__entity":{"type":"User","id":"alice"}},"y":{"__entity":{"type":"User"}}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{"x":{"__entity":{"type":"User","id":"alice"}},"s":[[],{},[1,1,"1",true]],"e":{},"l":[]},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":[],"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":{},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":"crm.customer","now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":{"path":"crm.customer"},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":{"path":"crm.customer","id":5},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":{"path":"crm.customer","id":""},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":{"path":"crm.customer","id":"c-1","attrs":[]},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":{"path":"crm.customer","id":"c-1","attrs":{}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":{"path":"crm.customer","id":"c-1","attrs":null},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":{"path":"crm.customer","id":"c-1","attrs":{"tenant":5,"f":1.5}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":{"path":"crm.customer","id":"c-1","attrs":{"owner":{"__entity":{"type":"User","id":"bob"}},"tags":["a","a"]}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read","resource":{"path":"nope","id":"x"},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"","resource":{"path":"crm.customer"},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":["read"],"resource":{"path":"crm.customer"},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"delete",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"fields":[],"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"fields":{},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"fields":["name","card.number","ssn"],"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"fields":["name","name"],"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"fields":["nope"],"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"fields":[1],"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"fields":"name","now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"dry_run":1,"explain":true,"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"dry_run":true,"explain":1,"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"alice","agents":["support-bot"]},"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":[],"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"token":"$c","action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"token":"$c","action":"read","resource":{"path":"crm.customer","id":"c-2"},"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"now":' . ($t + 900) . '}'],
        ['explain', '{"token":"$t","action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['explain', '{"token":"$c","action":"read",' . $c1 . ',"data":{"name":"Ann","tier":1},"now":' . $t . '}'],
        ['explain', '{"token":"$t","action":"update",' . $c1 . ',"data":{"email":"a@b","tier":2},"strict":true,"now":' . $t . '}'],
        // -- filter: records, lists, scalars, numeric keys, floats, big integers, code point order
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":{},"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":[],"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":null,"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":"text","now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":5,"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":1.5,"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":false,"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":' . $rec . ',"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":[' . $rec . ',{"region":"US","name":"B"},{"region":1},{"name":"no region"},{},[],"s",1,null,[{"region":"EU"}],{"region":"EU","0":"zero","name":"C"}],"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":' . $rec . ',"strict":true,"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":{"region":"EU","name":"A"},"strict":true,"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"read",' . $c1 . ',"data":' . $rec . ',"fields":["name","card.number"],"now":' . $t . '}'],
        ['filter', '{"token":"$c","action":"read",' . $c1 . ',"data":' . $rec . ',"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"delete",' . $c1 . ',"data":' . $rec . ',"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"update",' . $c1 . ',"data":{"email":"a@b","phone":"1","tier":2,"x":{"y":[]}},"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"update",' . $c1 . ',"data":{"email":"a@b","phone":"1","tier":2},"strict":true,"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"update",' . $c1 . ',"data":{"email":"a@b"},"strict":true,"now":' . $t . '}'],
        ['filter', '{"token":"$t","action":"update",' . $c1 . ',"data":[],"strict":true,"now":' . $t . '}'],
        // -- obligations applied later
        ['apply_obligations', '{"obligations":' . $ob . ',"data":[{"n":1,"a":1,"b":2,"c":3,"1":"one","o":{}},{"n":true,"a":1},{"n":1.0,"a":1},{"n":"1","a":1},{"a":1},{"n":1,"a":[],"c":[1],"z":0}]}'],
        ['apply_obligations', '{"obligations":{"fields":{"allow":["a"]},"row_filter":[{"column":"n","value":123456789012345678901234567890}]},"data":[{"n":123456789012345678901234567890,"a":1},{"n":123456789012345678901234567891,"a":2},{"n":1.2345678901234568e29,"a":3}]}'],
        ['apply_obligations', '{"obligations":{"fields":{"allow":["a"]},"row_filter":[{"column":"n","value":1.0}]},"data":[{"n":1,"a":1},{"n":1.0,"a":2},{"n":true,"a":3}]}'],
        ['apply_obligations', '{"obligations":{"fields":{"allow":["a"]},"row_filter":[{"column":"n","value":true}]},"data":[{"n":1,"a":1},{"n":1.0,"a":2},{"n":true,"a":3}]}'],
        ['apply_obligations', '{"obligations":{"fields":{"allow":["a"]},"row_filter":[{"column":"n","value":null}]},"data":[{"n":null,"a":1},{"a":2},{"n":0,"a":3},{"n":false,"a":4}]}'],
        ['apply_obligations', '{"obligations":{"fields":{"allow":["a"]},"row_filter":[{"column":"n","value":[1,true,{"k":1}]}]},"data":[{"n":[1,1,{"k":1.0}],"a":1},{"n":[1,true],"a":2},{"n":{"0":1},"a":3}]}'],
        ['apply_obligations', '{"obligations":{"fields":{"allow":["a"]},"row_filter":[{"column":"n","value":{}}]},"data":[{"n":{},"a":1},{"n":[],"a":2}]}'],
        ['apply_obligations', '{"obligations":{"fields":{"allow":["a"]},"row_filter":[{"column":"n","value":[]}]},"data":[{"n":{},"a":1},{"n":[],"a":2}]}'],
        ['apply_obligations', '{"obligations":{"fields":{"allow":["a"]},"row_filter":[{"column":5,"value":1},"x",{"value":1}]},"data":[{"n":1,"a":1}]}'],
        ['apply_obligations', '{"obligations":{"fields":{"allow":["a","a.b","l[]","l[].x"],"deny":["a.c","l[].y"],"redact":["a.d","m[]"]}},"data":{"a":{"b":1,"c":2,"d":3,"e":4},"l":[{"x":1,"y":2,"z":3},5,[{"x":1}]],"m":[1,{"q":1}],"u":{"v":1}}}'],
        ['apply_obligations', '{"obligations":{"fields":{"allow":"a","deny":{"a":1},"redact":[1,"r"]},"row_filter":{}},"data":{"a":1,"r":2}}'],
        ['apply_obligations', '{"obligations":{"fields":{}},"data":{}}'],
        ['apply_obligations', '{"obligations":{"fields":{}},"data":[]}'],
        ['apply_obligations', '{"obligations":{"fields":{}},"data":[[]]}'],
        ['apply_obligations', '{"obligations":{"fields":{}},"data":"s"}'],
        ['apply_obligations', '{"obligations":{"fields":[]},"data":{}}'],
        ['apply_obligations', '{"obligations":[],"data":{}}'],
        ['apply_obligations', '{"obligations":{},"data":{}}'],
        ['apply_obligations', '{"obligations":{"fields":{}}}'],
        ['apply_obligations', '{"obligations":{"fields":{"allow":["a"]}},"data":{"a":1,"b":2},"decision_id":"d-1234","now":' . $t . '}'],
        // -- spend, budgets, rate limit
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":1.0}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":true}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":-1}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":[]},"now":' . $t . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":9223372036854775808}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"USD","amount":1}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":8000}},"dry_run":true,"now":' . $t . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":8000}},"now":' . $t . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":8000}},"now":' . ($t + 1) . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":8000}},"now":' . ($t + 2) . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":0}},"now":' . ($t + 3) . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":0}},"now":' . ($t + 4) . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":0}},"now":' . ($t + 59) . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":0}},"now":' . ($t + 60) . '}'],
        // -- approval: the id is a hash of the canonical request, so it must be the same in both engines
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":15000},"note":"caf\u00e9 \ud83d\ude00 \u0001\u007f\u2028 \"q\" \\\\ /","tags":["b","a"],"n":{"10":1,"9":2,"-1":3,"08":4,"\uffff":5,"\ud83d\ude00":6},"e":{},"l":[],"big":-9223372036854775808},"now":' . ($t + 100) . '}', ['aid' => 'approval.id']],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":15000}},"dry_run":true,"now":' . ($t + 100) . '}', ['aid2' => 'approval.id']],
        ['approvals', '{}'],
        ['approve', '{"approval_id":"$aid2","by":"bob","now":' . ($t + 100) . '}'],
        ['approve', '{"approval_id":"$aid","by":"alice","now":' . ($t + 100) . '}'],
        ['approve', '{"approval_id":"$aid","by":"carol","now":' . ($t + 100) . '}'],
        ['approve', '{"approval_id":"$aid","by":"bob","ttl":1.0,"now":' . ($t + 100) . '}'],
        ['approve', '{"approval_id":"$aid","by":"bob","now":' . ($t + 100) . '}'],
        ['approvals', '{}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":15000},"note":"caf\u00e9 \ud83d\ude00 \u0001\u007f\u2028 \"q\" \\\\ /","tags":["a","b"],"n":{"9":2,"10":1,"-1":3,"08":4,"\ud83d\ude00":6,"\uffff":5},"l":[],"e":{},"big":-9223372036854775808},"dry_run":true,"now":' . ($t + 100) . '}'],
        ['authorize', '{"token":"$t",' . $refund . ',"context":{"spend":{"currency":"EUR","amount":15000},"note":"caf\u00e9 \ud83d\ude00 \u0001\u007f\u2028 \"q\" \\\\ /","tags":["a","b"],"n":{"9":2,"10":1,"-1":3,"08":4,"\ud83d\ude00":6,"\uffff":5},"l":{},"e":{},"big":-9223372036854775808},"dry_run":true,"now":' . ($t + 100) . '}'],
        // -- revocation with a numeric-looking id: the key "123" must stay a string in state.json
        ['revoke', '{"token_id":"123","now":' . $t . '}'],
        ['revoke', '{"token_id":123,"now":' . $t . '}'],
        ['revoke', '{"token":"$c","by":"me","now":' . $t . '}'],
        ['authorize', '{"token":"$c","action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['revoke', '{"token":"garbage"}'],
        // -- revoke by user
        ['revoke', '{"user":"dave","by":"hr","now":' . ($t - 1) . '}'],
        ['inspect_token', '{"token":"$d","now":' . $t . '}'],
        ['revoke', '{"user":"dave","token":"$t","token_id":"x","now":' . $t . '}'],
        ['inspect_token', '{"token":"$d","now":' . $t . '}'],
        ['authorize', '{"token":"$dc","action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['inspect_token', '{"token":"$t","now":' . $t . '}'],
        ['issue_token', '{"user":"dave","agent":"support-bot","role":"support-agent","groups":["support"],"task":"t-9","now":' . ($t + 1) . '}', ['dnew' => 'token']],
        ['inspect_token', '{"token":"$dnew","now":' . ($t + 1) . '}'],
        ['revoke', '{"user":"","now":' . $t . '}'],
        ['revoke', '{"user":null,"token_id":"x","now":' . $t . '}'],
        ['revoke', '{"user":5,"now":' . $t . '}'],
        ['revoke', '{"user":["dave"],"now":' . $t . '}'],
        ['revoke', '{"user":"123","now":99999999999999999999}'],
        ['revoke', '{"user":"nobody-\u00e9","by":5,"now":' . $t . '}'],
        ['audit_tail', '{"n":4}'],
        ['revoke', '{"user":"dave","now":' . ($t - 500) . '}'],
        ['revoke', '{"user":"dave","now":' . ($t + 5) . '}'],
        ['revoke', '{"user":"dave","now":' . ($t + 5) . '}'],
        // -- an ancestor's budget travels in `lim`
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":' . $cap . ',"now":' . $t . '}', ['lp' => 'token']],
        ['exchange_token', '{"subject_token":"$lp","actor":"refund-helper","cap":{"actions":["create"],"resources":["billing.refund/*"],"budget":{"EUR":6000}},"ttl":300,"now":' . $t . '}', ['lc' => 'token']],
        ['exchange_token', '{"subject_token":"$lc","actor":"summarizer","ttl":200,"now":' . $t . '}', ['lg' => 'token']],
        ['exchange_token', '{"subject_token":"$lp","actor":"refund-helper","cap":{"actions":["read"],"resources":["crm.customer/*"]},"ttl":300,"now":' . $t . '}', ['ln' => 'token']],
        ['exchange_token', '{"subject_token":"$ln","actor":"summarizer","ttl":200,"now":' . $t . '}', ['lgn' => 'token']],
        ['exchange_token', '{"subject_token":"$r","actor":"refund-helper","ttl":200,"now":' . $t . '}', ['rc' => 'token']],
        ['inspect_token', '{"token":"$lc","now":' . $t . '}'], ['inspect_token', '{"token":"$lg","now":' . $t . '}'],
        ['inspect_token', '{"token":"$ln","now":' . $t . '}'], ['inspect_token', '{"token":"$lgn","now":' . $t . '}'],
        ['inspect_token', '{"token":"$rc","now":' . $t . '}'], ['inspect_token', '{"token":"$c","now":' . $t . '}'],
        ['authorize', '{"token":"$lg","action":"create","resource":{"path":"billing.refund","id":"r-9"},"context":{"spend":{"currency":"EUR","amount":6001}},"now":' . ($t + 200) . '}'],
        ['authorize', '{"token":"$lg","action":"create","resource":{"path":"billing.refund","id":"r-9"},"context":{"spend":{"currency":"EUR","amount":6000}},"now":' . ($t + 100) . '}'],
        // -- strictness (0.3): line separators are data, base64url has one spelling, type names match in full
        ['revoke', '{"token_id":"a\u2028b\u2029c\u0085d\re","now":' . $t . '}'],
        ['revoke', '{"token_id":"after","now":' . $t . '}'],
        ['audit_tail', '{"n":2}'],
        ['inspect_token', '{"token":"!{{t}}","now":' . $t . '}'],
        ['inspect_token', '{"token":"{{t}}!","now":' . $t . '}'],
        ['inspect_token', '{"token":"{{t}}=","now":' . $t . '}'],
        ['inspect_token', '{"token":"{{t}} ","now":' . $t . '}'],
        ['inspect_token', '{"token":"{{t}}+","now":' . $t . '}'],
        ['inspect_token', '{"token":"{{t}}A","now":' . $t . '}'],
        ['inspect_token', '{"token":"{{far}}","now":99999999999999999999999}'],
        ['issue_token', '{"user":"dave","agent":"support-bot","role":"support-agent","groups":[{"type":"Group\n","id":"support"}],"now":' . $t . '}'],
        ['authorize', '{"token":"$t","action":"read",' . $c1 . ',"context":{"x":{"__entity":{"type":"User\n","id":"alice"}}},"now":' . $t . '}'],
        // -- audit
        ['audit_verify', '{}'],
        ['audit_tail', '{"n":3}'], ['audit_tail', '{"n":0}'], ['audit_tail', '{"n":-1}'], ['audit_tail', '{"n":1.0}'], ['audit_tail', '{"n":99999999999999999999}'],
        ['audit_tail', '{"n":1000}'],
        ['info', '{}'],
    ];
}

/** The same, for an engine in shadow mode that trusts caller-supplied chains. */
function differential_steps_shadow(): array
{
    $t = T0;
    $c1 = '"resource":{"path":"crm.customer","id":"c-1"}';
    $alice = '"chain":{"user":"alice","agents":["support-bot"]}';
    return [
        ['info', '{}'],
        ['authorize', '{' . $alice . ',"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"alice","agents":[]},"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"alice","agents":{}},"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"alice","agents":[1,"support-bot",null,"refund-helper"]},"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":{"agents":["support-bot"]},"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":{},"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":[],"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":"alice","action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":null,"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"dave","agents":["support-bot"]},"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"dave","agents":["support-bot"],"groups":["support"],"role":"auditor"},"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"dave","agents":["support-bot"],"groups":"support","role":"auditor"},"action":"update",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"alice","agents":["support-bot"],"groups":[]},"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"alice","agents":["support-bot"],"groups":{}},"action":"read",' . $c1 . ',"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"alice","agents":["support-bot"],"tenant":"acme","task":"t-1"},"action":"read","resource":{"path":"crm.customer","id":"c-1","attrs":{"tenant":"other"}},"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"alice","agents":["support-bot"],"tenant":"acme","task":"t-1"},"action":"read","resource":{"path":"crm.customer","id":"c-1","attrs":{"tenant":"acme"}},"explain":true,"now":' . $t . '}'],
        ['authorize', '{' . $alice . ',"action":"create","resource":{"path":"billing.refund","id":"r-1"},"context":{"spend":{"currency":"EUR","amount":100}},"now":' . $t . '}'],
        ['authorize', '{' . $alice . ',"action":"create","resource":{"path":"billing.refund","id":"r-1","attrs":{"customer_owner":"alice"}},"context":{"spend":{"currency":"EUR","amount":100}},"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"carol","agents":["support-bot"]},"action":"read","resource":{"path":"hr.salary","id":"s-1"},"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"carol","agents":["support-bot"]},"action":"read","resource":{"path":"hr.salary","id":"s-1","attrs":{"frozen":false}},"now":' . $t . '}'],
        ['authorize', '{"chain":{"user":"carol","agents":["support-bot"]},"action":"read","resource":{"path":"hr.salary","id":"s-1","attrs":{"frozen":"yes"}},"now":' . $t . '}'],
        ['filter', '{' . $alice . ',"action":"read",' . $c1 . ',"data":[{"region":"EU","name":"A","ssn":"1","card":{"number":"4"},"e":{},"l":[]},{"region":"US"},[],{}],"now":' . $t . '}'],
        ['filter', '{' . $alice . ',"action":"read",' . $c1 . ',"data":{"region":"US","name":"A"},"now":' . $t . '}'],
        ['filter', '{' . $alice . ',"action":"delete",' . $c1 . ',"data":{"region":"EU","e":{},"l":[],"n":1.0},"now":' . $t . '}'],
        ['filter', '{' . $alice . ',"action":"delete",' . $c1 . ',"data":[],"now":' . $t . '}'],
        ['filter', '{' . $alice . ',"action":"update",' . $c1 . ',"data":{"tier":1},"strict":true,"now":' . $t . '}'],
        ['filter', '{"action":"read",' . $c1 . ',"data":{},"now":' . $t . '}'],
        ['explain', '{' . $alice . ',"action":"read",' . $c1 . ',"data":"x","now":' . $t . '}'],
        ['issue_token', '{"user":"dave","agent":"support-bot","cap":{"actions":["read"]},"now":' . $t . '}'],
        ['issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["read"],"resources":["crm.customer/*"]},"tenant":"acme","task":"t-1","now":' . $t . '}', ['t' => 'token']],
        ['exchange_token', '{"subject_token":"$t","actor":"refund-helper","task":"t-2","ttl":60,"now":' . $t . '}'],
        ['exchange_token', '{"subject_token":"$t","actor":"refund-helper","task":"t-1","ttl":60,"now":' . $t . '}', ['c' => 'token']],
        ['exchange_token', '{"subject_token":"$c","actor":"summarizer","ttl":60,"now":' . $t . '}', ['g' => 'token']],
        ['exchange_token', '{"subject_token":"$g","actor":"summarizer","ttl":60,"now":' . $t . '}'],
        ['authorize', '{"token":"$g","action":"read","resource":{"path":"crm.customer","id":"c-1","attrs":{"tenant":"other"}},"now":' . $t . '}'],
        ['authorize', '{"token":"$g","action":"read","resource":{"path":"crm.customer","id":"c-1","attrs":{"tenant":"acme"}},"now":' . $t . '}'],
        ['authorize', '{"token":"$g","chain":{"user":"carol","agents":["support-bot"]},"action":"read",' . $c1 . ',"now":' . ($t + 61) . '}'],
        ['audit_tail', '{"n":50}'],
    ];
}

function section_interop(): void
{
    Run::begin();
    $why = python_available();
    if ($why !== null) {
        Run::note("4. interoperability with the Python reference: SKIPPED ($why)");
        return;
    }
    $cap = ['actions' => ['read', 'create', 'update'], 'resources' => ['crm.customer/*', 'billing.refund/*'], 'budget' => ['EUR' => 20000]];
    $work = Run::dir('interop');
    $capFile = Run::writeJson("$work/cap.json", $cap);
    $req = ['authorize', '--action', 'read', '--resource', 'crm.customer/c-1'];
    $c1 = ['action' => 'read', 'resource' => ['path' => 'crm.customer', 'id' => 'c-1']];

    // ---- a. tokens ----------------------------------------------------------------
    // PHP issues; the reference verifies with nothing but the PHP engine's public key
    $php = new Engine(Run::confConfig("$work/state-php"));
    $info = $php->call('info', []);
    $pyVerify = Run::writeJson("$work/py-verify.json", ['bundle_dir' => Run::$bundle, 'verify_only' => true, 'trusted_keys' => [$info['public_key']], 'max_depth' => 3]);
    $t = $php->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => $cap]);
    Run::eq(true, $t['ok'], 'a: PHP issues a token');
    [$code, $out, $err] = Run::py([...$req, '--token', $t['token'], '--config', $pyVerify]);
    $d = $code === 0 ? Json::decode($out) : new JsonObject();
    Run::ok($code === 0 && $d['effect'] === 'allow' && $d['principal']['user'] === 'alice' && $d['principal']['token_id'] === $t['token_id'],
        'a: the reference accepts a token issued by PHP (trusted_keys, verify_only)', $out . $err);
    $mine = $php->call('authorize', ['token' => $t['token']] + $c1);
    Run::ok(Json::pyEq($mine['obligations'], $d['obligations'] ?? null) && $mine['policies'] === ($d['policies'] ?? null), 'a: and reaches the same decision, policies and field obligations');

    $role = $php->call('issue_token', ['user' => 'dave', 'agent' => 'support-bot', 'role' => 'support-agent', 'groups' => ['support']]);
    Run::ok($role['ok'] === true && $role['role'] === 'support-agent', 'a: PHP issues a role token with live membership', Run::show($role));
    [$code, $out, $err] = Run::py(['call', 'inspect_token', '--input', Json::encode(new JsonObject(['token' => $role['token']])), '--config', $pyVerify]);
    $d = $code === 0 ? Json::decode($out) : new JsonObject();
    Run::ok($code === 0 && $d['valid'] === true && $d['claims']['role'] === 'support-agent'
        && Json::pyEq($d['claims']['grp'], [new JsonObject(['type' => 'Group', 'id' => 'support'])]), 'a: the reference reads `role` and `grp` from the PHP token', $out . $err);
    [$code, $out, $err] = Run::py([...$req, '--token', $role['token'], '--config', $pyVerify]);
    $d = $code === 0 ? Json::decode($out) : new JsonObject();
    Run::ok($code === 0 && $d['effect'] === 'allow' && $d['principal']['role'] === 'support-agent' && $d['policies'] === ['support-read-customer'],
        'a: the reference authorises it on the strength of `grp` (dave has no stored group)', $out . $err);
    $tampered = preg_replace_callback('/\.([^.]+)\./', static fn (array $m): string => '.' . strrev($m[1]) . '.', $t['token']);
    [$code, $out] = Run::py([...$req, '--token', $tampered, '--config', $pyVerify]);
    Run::ok($code === 2 && str_contains($out, 'token_invalid'), 'a: a tampered PHP token is refused by the reference', $out);
    $other = new Engine(Run::confConfig("$work/state-other"));
    $foreign = $other->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => $cap]);
    [$code, $out] = Run::py([...$req, '--token', $foreign['token'], '--config', $pyVerify]);
    Run::ok($code === 2 && str_contains($out, 'unknown key'), 'a: a token from a key the reference does not trust is refused', $out);
    $other->close();

    // the reference issues; PHP verifies with nothing but the reference's public key
    $pyCfg = Run::writeJson("$work/py.json", Run::confConfig("$work/state-py"));
    [$code, $pyToken, $err] = Run::py(['token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', "@$capFile", '--raw', '--config', $pyCfg]);
    $pyToken = trim($pyToken);
    Run::ok($code === 0 && substr_count($pyToken, '.') === 2, 'a: the reference issues a token', $err);
    $verifier = new Engine(['bundle_dir' => Run::$bundle, 'verify_only' => true, 'max_depth' => 3,
        'trusted_keys' => [trim((string) file_get_contents("$work/state-py/signing_key.pub.b64"))]]);
    Run::eq(false, $verifier->call('info', [])['can_issue'], 'a: a verify-only PHP engine cannot issue');
    Run::eq('no_signing_key', $verifier->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => $cap])['error']['code'] ?? null, 'a: and says so');
    $d = $verifier->call('authorize', ['token' => $pyToken] + $c1);
    Run::ok($d['ok'] === true && $d['effect'] === 'allow' && $d['principal']['user'] === 'alice', 'a: PHP accepts a token issued by the reference', Run::show($d));
    [$code, $out] = Run::py([...$req, '--token', $pyToken, '--config', $pyCfg]);
    $ref = Json::decode($out);
    Run::ok(Json::pyEq($d['obligations'], $ref['obligations']) && $d['policies'] === $ref['policies'] && $d['principal']['token_id'] === $ref['principal']['token_id'],
        'a: and reaches the same decision, policies and field obligations');
    [$code, $pyRole, $err] = Run::py(['token', 'issue', '--user', 'dave', '--agent', 'support-bot', '--role', 'support-agent', '--groups', 'support,nope,support', '--raw', '--config', $pyCfg]);
    $pyRole = trim($pyRole);
    Run::ok($code === 0, 'a: the reference issues a role token with live membership', $err);
    $ins = $verifier->call('inspect_token', ['token' => $pyRole]);
    Run::ok($ins['valid'] === true && $ins['claims']['role'] === 'support-agent' && Json::encode($ins['claims']['grp']) === '[{"type": "Group", "id": "support"}]',
        'a: PHP reads `role` and `grp` from the reference token', Run::show($ins));
    $d = $verifier->call('authorize', ['token' => $pyRole] + $c1);
    Run::ok($d['effect'] === 'allow' && $d['principal']['role'] === 'support-agent' && $d['policies'] === ['support-read-customer'],
        'a: PHP authorises it on the strength of `grp`', Run::show($d));
    $bad = preg_replace_callback('/\.([^.]+)\./', static fn (array $m): string => '.' . strrev($m[1]) . '.', $pyToken);
    Run::eq('token_invalid', $verifier->call('authorize', ['token' => $bad] + $c1)['reason'] ?? null, 'a: a tampered reference token is refused by PHP');
    Run::eq('token_invalid', $php->call('authorize', ['token' => $pyToken] + $c1)['reason'] ?? null, 'a: a reference token is refused by a PHP engine that does not trust its key');
    $verifier->close();
    // the PHP command line produces what the engine does
    $cliCfg = Run::writeJson("$work/php-cli.json", Run::confConfig("$work/state-php"));
    [$code, $cliToken] = Run::php(['token', 'issue', '--user', 'dave', '--agent', 'support-bot', '--role', 'support-agent', '--groups', 'support', '--raw', '--config', $cliCfg]);
    [$code2, $out] = Run::py([...$req, '--token', trim($cliToken), '--config', $pyVerify]);
    Run::ok($code === 0 && $code2 === 0 && Json::decode($out)['principal']['role'] === 'support-agent', 'a: `smartdelegate-php token issue --role --groups --raw` gives a token the reference accepts', $out);

    // ---- F-1: an ancestor's budget is enforced by a verify-only engine that has its own state directory ----
    $refundCap = ['actions' => ['create'], 'resources' => ['billing.refund/*'], 'budget' => ['EUR' => 10000]];
    $kidCap = ['actions' => ['create'], 'resources' => ['billing.refund/*'], 'budget' => ['EUR' => 6000]];
    $spend5000 = Run::writeJson("$work/spend5000.json", ['spend' => ['currency' => 'EUR', 'amount' => 5000]]);
    $kidCapFile = Run::writeJson("$work/kidcap.json", $kidCap);
    $refundCapFile = Run::writeJson("$work/refundcap.json", $refundCap);
    // PHP issues; the reference verifies with its own, empty, state directory
    $issuer = new Engine(Run::confConfig("$work/f1-php-issuer"));
    $parent = $issuer->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => $refundCap]);
    $kids = [];
    for ($i = 0; $i < 3; $i++) {
        $kids[] = $issuer->call('exchange_token', ['subject_token' => $parent['token'], 'actor' => 'refund-helper', 'ttl' => 300, 'cap' => $kidCap]);
    }
    $limClaim = $issuer->call('inspect_token', ['token' => $kids[0]['token']])['claims']['lim'] ?? null;
    Run::ok($limClaim instanceof JsonObject && Json::compact($limClaim) === '{"' . $parent['token_id'] . '":{"EUR":10000}}', 'F-1: a child token carries its parent\'s budget in `lim`', Run::show($limClaim));
    Run::ok(!str_contains(Tokens::b64uDec(explode('.', $parent['token'])[1]), '"lim"'), 'F-1: a root token has no `lim` claim');
    $pyF1 = Run::writeJson("$work/f1-py-verify.json", ['bundle_dir' => Run::$bundle, 'state_dir' => "$work/f1-py-verifier", 'verify_only' => true, 'max_depth' => 3,
        'trusted_keys' => [$issuer->call('info')['public_key']]]);
    $f1 = [];
    foreach ($kids as $k) {
        [$code, $out] = Run::py(['authorize', '--action', 'create', '--resource', 'billing.refund/r', '--context', "@$spend5000", '--token', $k['token'], '--config', $pyF1]);
        $f1[] = $code . ':' . (Json::decode($out)['reason'] ?? '?');
    }
    Run::eq(['0:policy_permit', '0:policy_permit', '2:budget_exceeded'], $f1, 'F-1: PHP issues, the reference (verify-only, own state) allows 5000 + 5000 through two children and denies the third: parent budget 10000');
    $issuer->close();
    // the reference issues; PHP verifies with its own, empty, state directory
    $pyIssuer = Run::writeJson("$work/f1-py-issuer.json", Run::confConfig("$work/f1-py-issuer"));
    [, $pyParent] = Run::py(['token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', "@$refundCapFile", '--raw', '--config', $pyIssuer]);
    $pyKids = [];
    for ($i = 0; $i < 3; $i++) {
        [$code, $kid, $err] = Run::py(['token', 'exchange', '--token', trim($pyParent), '--actor', 'refund-helper', '--ttl', '300', '--cap', "@$kidCapFile", '--raw', '--config', $pyIssuer]);
        $pyKids[] = trim($kid);
    }
    $verifier = new Engine(['bundle_dir' => Run::$bundle, 'state_dir' => "$work/f1-php-verifier", 'verify_only' => true, 'max_depth' => 3,
        'trusted_keys' => [trim((string) file_get_contents("$work/f1-py-issuer/signing_key.pub.b64"))]]);
    $ins = $verifier->call('inspect_token', ['token' => $pyKids[0]]);
    Run::ok(($ins['valid'] ?? null) === true && count($ins['claims']['lim'] ?? []) === 1 && Json::compact(array_values($ins['claims']['lim']->m)[0]) === '{"EUR":10000}',
        'F-1: PHP reads `lim` from a child token issued by the reference', Run::show($ins));
    $f1 = [];
    foreach ($pyKids as $k) {
        $d = $verifier->call('authorize', ['token' => $k, 'action' => 'create', 'resource' => ['path' => 'billing.refund', 'id' => 'r'], 'context' => ['spend' => ['currency' => 'EUR', 'amount' => 5000]]]);
        $f1[] = ($d['effect'] ?? '?') . ':' . ($d['reason'] ?? '?');
    }
    Run::eq(['allow:policy_permit', 'allow:policy_permit', 'deny:budget_exceeded'], $f1, 'F-1: the reference issues, PHP (verify-only, own state) allows two and denies the third');
    Run::ok(Json::decode((string) file_get_contents("$work/f1-php-verifier/state.json"))['limits']->isEmpty(), 'F-1: (control) the PHP verifier\'s own state has no limits: the denial came from `lim`');
    $verifier->close();

    // ---- b. signed bundles ----------------------------------------------------------
    [, $out] = Run::py(['info', '--bundle', Run::$bundle]);
    $pyVersion = Json::decode($out)['policy_version'];
    Run::ok(strlen((string) $pyVersion) === 64 && $pyVersion === $info['policy_version'], 'b: both compute the same bundle version', "$pyVersion vs {$info['policy_version']}");
    foreach ([['php', 'python'], ['python', 'php']] as [$signer, $loader]) {
        $b = "$work/bundle-$signer";
        Run::copyDir(Run::$bundle, $b);
        $prefix = "$work/k-$signer";
        $run = $signer === 'php' ? [Run::class, 'php'] : [Run::class, 'py'];
        [$c1x, , $e1] = $run(['bundle', 'keygen', $prefix]);
        [$c2x, $signOut, $e2] = $run(['bundle', 'sign', '--key', "$prefix.key", '--bundle', $b]);
        Run::ok($c1x === 0 && $c2x === 0 && is_file("$b/bundle.sig.json"), "b: $signer generates a key and signs a bundle", $e1 . $e2);
        Run::ok(str_contains($signOut, (string) $pyVersion), "b: $signer signs the version both agree on", $signOut);
        Run::eq('0600', substr(sprintf('%o', fileperms("$prefix.key")), -4), "b: the private key written by $signer is mode 0600");
        $signed = Run::writeJson("$work/signed-$signer.json", ['bundle_dir' => $b, 'bundle_public_key' => (string) file_get_contents("$prefix.pub")]);
        $load = $loader === 'php' ? [Run::class, 'php'] : [Run::class, 'py'];
        [$code, $out, $err] = $load(['info', '--config', $signed]);
        $v = $code === 0 ? Json::decode($out) : new JsonObject();
        Run::ok($code === 0 && is_string($v['bundle_signed_by']) && strlen($v['bundle_signed_by']) === 16 && $v['policy_version'] === $pyVersion,
            "b: a bundle signed by $signer loads in $loader", $out . $err);
        if ($loader === 'php') {
            $e = new Engine(['bundle_dir' => $b, 'bundle_public_key' => (string) file_get_contents("$prefix.pub")]);
            Run::eq($v['bundle_signed_by'], $e->call('info', [])['bundle_signed_by'], 'b: and in the PHP engine in-process');
            $e->close();
        }
        $wrongKey = Run::writeJson("$work/wrong-$signer.json", ['bundle_dir' => $b, 'bundle_public_key' => $info['public_key']]);
        [$code, $out, $err] = $load(['info', '--config', $wrongKey]);
        Run::ok($code !== 0 && str_contains($out . $err, 'bundle_signature'), "b: $loader refuses it under another public key", $out . $err);
        $p = "$b/entities.json";
        file_put_contents($p, preg_replace('/"region": "EU"/', '"region": "US"', (string) file_get_contents($p), 1));
        [$code, $out, $err] = $load(['info', '--config', $signed]);
        Run::ok($code !== 0 && str_contains($out . $err, 'bundle_signature'), "b: $loader detects a file changed after $signer signed", $out . $err);
        unlink("$b/bundle.sig.json");
        [$code, $out, $err] = $load(['info', '--config', $signed]);
        Run::ok($code !== 0 && str_contains($out . $err, 'bundle_unsigned'), "b: $loader refuses the bundle without its signature", $out . $err);
    }

    // ---- c. audit logs --------------------------------------------------------------
    $t2 = $php->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => $cap, 'tenant' => 'acme', 'task' => "t-\u{e9}\u{1F600}"]);
    $php->call('authorize', ['token' => $t2['token']] + $c1);
    $php->call('filter', ['token' => $t2['token'], 'data' => new JsonObject(['name' => "Zo\u{eb} \u{2028}", 'ssn' => '1', 'region' => 'EU'])] + $c1);
    $php->call('authorize', ['token' => $t2['token'], 'action' => 'create', 'resource' => ['path' => 'billing.refund', 'id' => 'r-1'],
        'context' => ['spend' => ['currency' => 'EUR', 'amount' => 15000]]]);
    $php->call('authorize', ['token' => 'garbage'] + $c1);
    $php->call('revoke', ['token' => $t2['token'], 'by' => 'test']);
    $mine = $php->call('audit_verify', []);
    Run::ok($mine['ok'] === true && $mine['records'] >= 9, 'c: PHP writes an audit log', Run::show($mine));
    [$code, $out, $err] = Run::py(['audit', 'verify', '--config', $cliCfg]);
    $v = $code === 0 ? Json::decode($out) : new JsonObject();
    Run::ok($code === 0 && $v['records'] === $mine['records'] && $v['head'] === $mine['head'],
        'c: the reference verifies the log written by PHP: same record count, same head hash', $out . $err);
    $log = "$work/state-php/audit.jsonl";
    $original = (string) file_get_contents($log);
    file_put_contents($log, preg_replace('/"user":"alice"/', '"user":"mallory"', $original, 1));
    [$code, $out, $err] = Run::py(['audit', 'verify', '--config', $cliCfg]);
    Run::ok($code !== 0 && str_contains($out . $err, 'audit_broken'), 'c: the reference detects a tampered PHP log', $out . $err);
    Run::eq('audit_broken', $php->call('audit_verify', [])['error']['code'] ?? null, 'c: PHP detects it too');
    $lines = explode("\n", rtrim($original, "\n"));
    file_put_contents($log, implode("\n", array_merge(array_slice($lines, 0, 2), array_slice($lines, 3))) . "\n");
    Run::eq('audit_broken', $php->call('audit_verify', [])['error']['code'] ?? null, 'c: PHP detects a deleted line');
    [$code, $out, $err] = Run::py(['audit', 'verify', '--config', $cliCfg]);
    Run::ok($code !== 0 && str_contains($out . $err, 'audit_broken'), 'c: the reference detects a deleted line', $out . $err);
    file_put_contents($log, $original);
    Run::eq(true, $php->call('audit_verify', [])['ok'], 'c: the restored log verifies again');
    $php->close();

    Run::py([...$req, '--token', $pyToken, '--config', $pyCfg]);
    Run::py(['authorize', '--action', 'create', '--resource', 'billing.refund/r-1', '--context', '{"spend": {"currency": "EUR", "amount": 15000}}', '--token', $pyToken, '--config', $pyCfg]);
    [, $out] = Run::py(['audit', 'verify', '--config', $pyCfg]);
    $ref = Json::decode($out);
    $pyLog = "$work/state-py/audit.jsonl";
    $v = Audit::verify($pyLog);
    Run::ok($ref['records'] >= 5 && $v['records'] === $ref['records'] && $v['head'] === $ref['head'], 'c: PHP verifies the log written by the reference: same record count, same head hash',
        Run::show($v) . ' vs ' . $out);
    [$code, $out, $err] = Run::php(['audit', 'verify', '--config', $pyCfg]);
    Run::ok($code === 0 && Json::decode($out)['head'] === $ref['head'], 'c: and so does `smartdelegate-php audit verify` on the reference state directory', $out . $err);
    $original = (string) file_get_contents($pyLog);
    file_put_contents($pyLog, preg_replace('/"effect":"allow"/', '"effect":"deny"', $original, 1));
    $caught = '';
    try {
        Audit::verify($pyLog);
    } catch (EngineError $e) {
        $caught = $e->errorCode;
    }
    Run::eq('audit_broken', $caught, 'c: PHP detects a tampered reference log');
    [$code, $out, $err] = Run::php(['audit', 'verify', '--config', $pyCfg]);
    Run::ok($code === 1 && str_contains($out . $err, 'audit_broken'), 'c: and the PHP command line refuses to start on it', $out . $err);
    file_put_contents($pyLog, $original);

    // ---- d. one state directory, both engines, one signing key ----------------------------
    $shared = "$work/shared";
    $sharedCfg = Run::writeJson("$work/shared.json", Run::confConfig($shared));
    $e = new Engine(Run::confConfig($shared));   // long-lived: sees the reference's writes on its next call
    $spend = Run::writeJson("$work/spend.json", ['spend' => ['currency' => 'EUR', 'amount' => 8000]]);
    $refund = ['authorize', '--action', 'create', '--resource', 'billing.refund/r-1', '--context', "@$spend"];
    $phpRefund = ['action' => 'create', 'resource' => ['path' => 'billing.refund', 'id' => 'r-1'], 'context' => ['spend' => ['currency' => 'EUR', 'amount' => 8000]]];
    $tok = $e->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => $cap])['token'];                                    // 1
    [$code, $out, $err] = Run::py([...$refund, '--token', $tok, '--config', $sharedCfg]);                                                   // 2
    Run::ok($code === 0, 'd: the reference accepts the PHP token (same signing key file) and spends 8000', $out . $err);
    Run::eq('allow', $e->call('authorize', ['token' => $tok] + $phpRefund)['effect'] ?? null, 'd: PHP spends another 8000');                 // 3
    [$code, $out] = Run::py([...$refund, '--token', $tok, '--config', $sharedCfg]);                                                         // 4
    Run::ok($code === 2 && Json::decode($out)['reason'] === 'budget_exceeded', 'd: the reference sees both spends: a third 8000 exceeds 20000', $out);
    $d = $e->call('authorize', ['token' => $tok] + $phpRefund);                                                                           // 5
    Run::ok($d['reason'] === 'budget_exceeded' && str_contains((string) $d['detail'], 'already spent 16000'), 'd: PHP sees both spends too', Run::show($d));
    $narrow = Run::writeJson("$work/narrow.json", ['actions' => ['read'], 'resources' => ['crm.customer/c-1'], 'deny_labels' => ['pii']]);
    [$code, $child, $err] = Run::py(['token', 'exchange', '--token', $tok, '--actor', 'refund-helper', '--cap', "@$narrow", '--ttl', '300', '--raw', '--config', $sharedCfg]);   // 6
    $child = trim($child);
    Run::ok($code === 0, 'd: the reference delegates from the PHP token', $err);
    $d = $e->call('authorize', ['token' => $child] + $c1);                                                                                // 7
    Run::ok($d['effect'] === 'allow' && $d['principal']['chain'] === ['support-bot', 'refund-helper'], 'd: PHP accepts the child token and reads the chain', Run::show($d));
    [$code, $phpChild] = Run::php(['token', 'exchange', '--token', $tok, '--actor', 'summarizer', '--ttl', '300', '--raw', '--config', $sharedCfg]);    // 8
    [$code2, $out] = Run::py([...$req, '--token', trim($phpChild), '--config', $sharedCfg]);                                                // 9
    Run::ok($code === 0 && $code2 === 0 && Json::pyEq(Json::decode($out)['principal']['chain'], ['support-bot', 'summarizer']),
        'd: the reference accepts a child delegated by the PHP command line', $out);
    [$code] = Run::py(['token', 'revoke', '--token', $tok, '--config', $sharedCfg]);                                                        // 10
    Run::eq(0, $code, 'd: the reference revokes the parent');
    Run::eq('token_revoked', $e->call('authorize', ['token' => $child] + $c1)['reason'] ?? null, 'd: PHP sees the revocation: the whole subtree is refused');   // 11
    $t3 = $e->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => $cap]);                                             // 12
    Run::eq($t3['token_id'], $e->call('revoke', ['token_id' => $t3['token_id']])['revoked'] ?? null, 'd: PHP revokes a token');              // 13
    [$code, $out] = Run::py([...$req, '--token', $t3['token'], '--config', $sharedCfg]);                                                    // 14
    Run::ok($code === 2 && Json::decode($out)['reason'] === 'token_revoked', 'd: the reference sees the PHP revocation', $out);
    // revoke by user (offboarding), in both directions
    $erin = $e->call('issue_token', ['user' => 'erin', 'agent' => 'support-bot', 'cap' => $cap]);                                            // 15
    Run::ok($erin['ok'] === true && array_key_exists('task', $erin) && $erin['task'] === null, 'd: PHP issues a token for erin (result carries "task": null)', Run::show($erin));
    $rv = $e->call('revoke', ['user' => 'erin', 'by' => 'hr']);                                                                             // 16
    Run::ok($rv['ok'] === true && $rv['revoked_user'] === 'erin' && is_int($rv['issued_up_to']), 'd: PHP revokes the user erin', Run::show($rv));
    [$code, $out] = Run::py([...$req, '--token', $erin['token'], '--config', $sharedCfg]);                                                  // 17
    $d = Json::decode($out);
    Run::ok($code === 2 && $d['reason'] === 'token_revoked' && $d['principal']['user'] === 'erin', 'd: the reference refuses erin\'s token: token_revoked, attributed to her', $out);
    $bob = $e->call('issue_token', ['user' => 'bob', 'agent' => 'support-bot', 'cap' => $cap, 'task' => 'ticket-9']);                        // 18
    Run::ok($bob['ok'] === true && $bob['task'] === 'ticket-9', 'd: PHP issues a token for bob (result carries the task)', Run::show($bob));
    [$code, $bobChild] = Run::py(['token', 'exchange', '--token', $bob['token'], '--actor', 'refund-helper', '--ttl', '300', '--raw', '--config', $sharedCfg]);   // 19
    Run::eq('allow', $e->call('authorize', ['token' => $bob['token']] + $c1)['effect'] ?? null, 'd: (control) bob\'s token works');           // 20
    [$code, $out, $err] = Run::py(['token', 'revoke', '--user', 'bob', '--config', $sharedCfg]);                                            // 21
    Run::ok($code === 0 && Json::decode($out)['revoked_user'] === 'bob', 'd: the reference revokes the user bob', $out . $err);
    $d = $e->call('authorize', ['token' => $bob['token']] + $c1);                                                                         // 22
    Run::ok($d['reason'] === 'token_revoked' && $d['principal']['user'] === 'bob', 'd: PHP refuses bob\'s token: token_revoked, attributed to him', Run::show($d));
    Run::eq('token_revoked', $e->call('authorize', ['token' => trim($bobChild)] + $c1)['reason'] ?? null, 'd: and the sub-agent token the reference derived from it');   // 23
    [$code, $out] = Run::php(['token', 'revoke', '--user', 'carol', '--config', $sharedCfg]);                                               // 24
    Run::ok($code === 0 && Json::decode($out)['revoked_user'] === 'carol', 'd: `smartdelegate-php token revoke --user` works', $out);
    $mine = $e->call('audit_verify', []);
    [$code, $out, $err] = Run::py(['audit', 'verify', '--config', $sharedCfg]);
    $ref = $code === 0 ? Json::decode($out) : new JsonObject();
    Run::ok($mine['ok'] === true && $mine['records'] === 24 && $ref['records'] === 24 && $ref['head'] === $mine['head'],
        'd: 24 interleaved operations left one valid chain of 24 records, verified by both', Run::show($mine) . ' / ' . $out . $err);
    $rawState = (string) file_get_contents("$shared/state.json");
    $state = Json::decode($rawState);
    Run::ok($state instanceof JsonObject && count($state['revoked']) === 2 && count($state['limits']) >= 2 && $state['revoked_users']->keys() === ['erin', 'bob', 'carol'],
        'd: state.json holds the revocations, the revoked users and the budgets', $rawState);
    [, $out] = Run::py(['audit', 'tail', '-n', '1', '--config', $sharedCfg]);
    $last = Json::decode(trim($out));
    Run::ok($last['event'] === 'user_revoked' && $last['user'] === 'carol' && $last['by'] === 'cli' && is_int($last['issued_up_to']), 'd: the audit event is user_revoked {user, issued_up_to, by}', $out);

    // The lock is the same lock: flock(2) on <state_dir>/lock. No time thresholds: the holder says in
    // marker files what it is doing, and the proof is the order of events, however slow the machine is.
    //   holder: takes the lock, writes `held`; waits for `calling`; waits a little more so the caller can
    //           reach flock(); writes `releasing` WHILE STILL HOLDING the lock; then unlocks.
    //   caller: must not come back before `releasing` exists.
    $holderCode = <<<'PY'
import fcntl, os, sys, time
lock, d = sys.argv[1], sys.argv[2]
f = open(lock, "a+b")
fcntl.flock(f.fileno(), fcntl.LOCK_EX)
open(os.path.join(d, "held"), "w").close()
deadline = time.time() + 120
while not os.path.exists(os.path.join(d, "calling")) and time.time() < deadline:
    time.sleep(0.01)
time.sleep(0.5)
open(os.path.join(d, "releasing"), "w").close()
fcntl.flock(f.fileno(), fcntl.LOCK_UN)
PY;
    $marks = Run::dir('lock-marks');
    $holder = proc_open(['python3', '-c', $holderCode, "$shared/lock", $marks], [1 => ['file', '/dev/null', 'w'], 2 => ['file', "$marks/err", 'w']], $pipes);
    Run::$procs[] = $holder;
    $held = Run::waitFor(static fn (): bool => file_exists("$marks/held"), 120);
    touch("$marks/calling");
    $r = $e->call('info', []);
    clearstatcache();
    $after = file_exists("$marks/releasing");
    proc_close($holder);
    Run::ok($held && $r['ok'] === true && $after, 'd: a PHP call made while a Python process holds flock on the lock file returns only after that process has started releasing it',
        'held=' . Run::show($held) . ' releasing marker present when the call returned=' . Run::show($after) . ' ' . @file_get_contents("$marks/err"));
    // the other way round: PHP holds the lock; the reference CLI must not finish (nor print anything) until it is released
    $f = fopen("$shared/lock", 'a+b');
    flock($f, LOCK_EX);
    $bg = proc_open(['python3', '-m', 'sf_smartdelegate', 'info', '--config', $sharedCfg], [1 => ['file', "$work/bg.out", 'w'], 2 => ['file', "$work/bg.err", 'w']], $pipes, null, array_merge(getenv(), Run::pyEnv()));
    Run::$procs[] = $bg;
    usleep(1500000);   // long enough, on an idle machine, for the CLI to reach the lock; being too short cannot fail the test, only weaken it
    clearstatcache();
    $running = proc_get_status($bg)['running'];
    $silent = filesize("$work/bg.out") === 0;
    flock($f, LOCK_UN);
    fclose($f);
    $exited = Run::waitFor(static fn (): bool => !proc_get_status($bg)['running'], 180);
    proc_close($bg);
    Run::ok($running && $silent && $exited && str_contains((string) file_get_contents("$work/bg.out"), '"ok": true'),
        'd: the reference neither finishes nor prints while PHP holds the lock, and proceeds once it is released',
        'running=' . Run::show($running) . ' silent=' . Run::show($silent) . ' exited=' . Run::show($exited) . ' ' . @file_get_contents("$work/bg.err"));
    $e->close();

    // ---- e. the same requests, step by step, in both engines ----------------------------------
    $n = $same = $sameText = 0;
    foreach ([['strict', [], differential_steps()], ['shadow', ['mode' => 'shadow', 'trust_caller_chain' => true, 'max_ttl' => 1800, 'default_ttl' => 120], differential_steps_shadow()]] as [$label, $extra, $steps]) {
    $ref = new Reference('engine', Run::confConfig("$work/diff-py-$label", $extra));
    $php = new Engine(Run::confConfig("$work/diff-php-$label", $extra));
    $vars = ['php' => [], 'py' => []];
    foreach ($steps as $step) {
        [$op, $input] = $step;
        $results = [];
        foreach (['php', 'py'] as $side) {
            // "{{name}}" inside a string is replaced too, so a saved token can be damaged on purpose
            $text = preg_replace_callback('/\{\{(\w+)\}\}/', static fn (array $m): string => (string) ($vars[$side][$m[1]] ?? $m[0]), $input);
            $payload = Json::encode(Conformance::substitute(Json::decode($text), $vars[$side]));
            $text = $side === 'php' ? $php->callJson($op, $payload) : $ref->ask(Json::encode([$op, Json::decode($payload)]));
            $results[$side] = Json::decode($text);
            foreach ($step[2] ?? [] as $name => $key) {
                $cur = $results[$side];
                foreach (explode('.', $key) as $part) {
                    $cur = $cur instanceof JsonObject ? $cur->get($part) : null;
                }
                $vars[$side][$name] = $cur;
            }
        }
        $n++;
        $a = masked($results['php'], true);
        $b = masked($results['py'], true);
        $same += $a === $b ? 1 : 0;
        $sameText += masked($results['php'], false) === masked($results['py'], false) ? 1 : 0;
        if (getenv('SHOW_TEXT_DIFFS') && masked($results['php'], false) !== masked($results['py'], false)) {
            echo "  text differs for $op $input\n    php:    ", masked($results['php'], false), "\n    python: ", masked($results['py'], false), "\n";
        }
        Run::ok($a === $b, "e ($label): same result for $op " . (strlen($input) > 150 ? substr($input, 0, 150) . '...' : $input), "php:    $a\n       python: $b");
    }
    // the state files and audit logs the two runs left behind have the same shape too
    $stateOf = static fn (string $f): string => is_file($f) ? masked(Json::decode((string) file_get_contents($f)), true) : '(no state.json)';
    $sp = $stateOf("$work/diff-php-$label/state.json");
    $sr = $stateOf("$work/diff-py-$label/state.json");
    Run::ok($sp === $sr, "e ($label): state.json has the same content in both", "php:    $sp\n       python: $sr");
    $lp = explode("\n", trim((string) file_get_contents("$work/diff-php-$label/audit.jsonl")));
    $lr = explode("\n", trim((string) file_get_contents("$work/diff-py-$label/audit.jsonl")));
    $auditSame = count($lp) === count($lr);
    foreach ($auditSame ? $lp : [] as $i => $line) {
        $x = masked(Json::decode($line), true);
        $y = masked(Json::decode($lr[$i]), true);
        if ($x !== $y) {
            $auditSame = false;
            echo "       audit record " . ($i + 1) . " differs\n       php:    $x\n       python: $y\n";
            break;
        }
    }
    Run::ok($auditSame, "e ($label): every audit record has the same fields and values in both (" . count($lp) . ' records)');
    Run::ok(Audit::verify("$work/diff-py-$label/audit.jsonl")['records'] === count($lr), 'e: and PHP verifies the reference log of that run');
    $php->close();
    $ref->close();
    }

    // approval ids are a hash of the canonical request, resource attributes included: byte-identical in both engines
    $ref = new Reference('engine', Run::confConfig("$work/aid-py"));
    $php = new Engine(Run::confConfig("$work/aid-php"));
    $tokJson = '{"user":"alice","agent":"support-bot","cap":{"actions":["create"],"resources":["billing.refund/*"],"budget":{"EUR":20000}},"now":' . T0 . '}';
    $aidTok = ['php' => Json::decode($php->callJson('issue_token', $tokJson))['token'], 'py' => Json::decode($ref->ask('["issue_token",' . $tokJson . ']'))['token']];
    $attrSets = [
        'no attrs' => null,
        'attrs null' => 'null',
        'attrs {}' => '{}',
        'a string' => '{"owner":"bob"}',
        'another string' => '{"owner":"carol"}',
        'nested object' => '{"meta":{"dept":{"name":"ops","floor":3}},"owner":"bob"}',
        'nested object, keys shuffled' => '{"owner":"bob","meta":{"dept":{"floor":3,"name":"ops"}}}',
        'empty nested object' => '{"meta":{}}',
        'empty nested list' => '{"meta":[]}',
        'non-ASCII string' => '{"city":"Z\u00fcrich \ud83d\ude00 \u2028"}',
        'integer' => '{"n":1}',
        'the same digit as a string' => '{"n":"1"}',
        'a larger integer' => '{"n":9223372036854775807}',
        'numeric-looking keys' => '{"10":"a","9":"b","-1":"c","08":"d"}',
        'numeric-looking keys, shuffled' => '{"08":"d","-1":"c","9":"b","10":"a"}',
        'a non-BMP key and U+FFFF' => '{"\uffff":1,"\ud83d\ude00":2}',
    ];
    $idsBySet = [];
    foreach ($attrSets as $what => $attrs) {
        $pair = [];
        foreach (['php', 'py'] as $side) {
            $reqJson = '{"token":"' . $aidTok[$side] . '","action":"create","resource":{"path":"billing.refund","id":"r-1"' . ($attrs === null ? '' : ',"attrs":' . $attrs)
                . '},"context":{"spend":{"currency":"EUR","amount":15000}},"dry_run":true,"now":' . T0 . '}';
            $res = Json::decode($side === 'php' ? $php->callJson('authorize', $reqJson) : $ref->ask('["authorize",' . $reqJson . ']'));
            $pair[$side] = $res instanceof JsonObject && $res['approval'] instanceof JsonObject ? $res['approval']['id'] : Json::encode($res);
        }
        $idsBySet[$what] = $pair['php'];
        Run::ok(is_string($pair['php']) && strlen($pair['php']) === 24 && $pair['php'] === $pair['py'], "approval id: PHP and the reference compute the same id ($what)", "php {$pair['php']} / python {$pair['py']}");
    }
    Run::ok($idsBySet['no attrs'] === $idsBySet['attrs null'] && $idsBySet['no attrs'] === $idsBySet['attrs {}'], 'approval id: no attrs, attrs null and attrs {} are the same request');
    Run::ok($idsBySet['nested object'] === $idsBySet['nested object, keys shuffled'] && $idsBySet['numeric-looking keys'] === $idsBySet['numeric-looking keys, shuffled'],
        'approval id: key order does not matter');
    $distinct = array_unique(array_values(array_diff_key($idsBySet, ['attrs null' => 1, 'attrs {}' => 1, 'nested object, keys shuffled' => 1, 'numeric-looking keys, shuffled' => 1])));
    Run::eq(12, count($distinct), 'approval id: every different set of attributes has its own id ({} vs [], 1 vs "1", bob vs carol)');
    // and an approval given for one resource is not consumed by the same request about another
    $with = static fn (string $owner, bool $dry = false): array => $php->call('authorize', ['token' => $aidTok['php'], 'action' => 'create',
        'resource' => ['path' => 'billing.refund', 'id' => 'r-1', 'attrs' => ['customer_owner' => $owner]], 'context' => ['spend' => ['currency' => 'EUR', 'amount' => 15000]], 'now' => T0, 'dry_run' => $dry]);
    $first = $with('emp-1');
    $php->call('approve', ['approval_id' => $first['approval']['id'], 'by' => 'bob', 'now' => T0]);
    Run::eq('approval_required', $with('emp-2')['reason'] ?? null, 'approval: an approval for emp-1 is not consumed by the same request naming emp-2');
    Run::eq('policy_permit', $with('emp-1')['reason'] ?? null, 'approval: and is still there for emp-1');
    $php->close();
    $ref->close();

    // OIDC ID tokens after the first run against a real provider: azp, several audiences, iat against the
    // revoke cut-off, a nested group claim. The same signed tokens go to both engines.
    $pair = sodium_crypto_sign_keypair();
    $idJwk = ['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => 'k1', 'x' => Tokens::b64u(sodium_crypto_sign_publickey($pair))];
    $signId = static function (array $claims) use ($pair): string {
        $h = Tokens::b64u('{"alg":"EdDSA","kid":"k1"}');
        $b = Tokens::b64u(Json::compact(Json::fromNative($claims)));
        return "$h.$b." . Tokens::b64u(sodium_crypto_sign_detached("$h.$b", sodium_crypto_sign_secretkey($pair)));
    };
    $idBase = ['iss' => 'https://idp.test', 'aud' => 'client-1', 'sub' => 'dave', 'iat' => T0, 'exp' => T0 + 600];
    $roles = ['realm_access' => ['roles' => ['support', 'offline_access']]];
    $idCases = [
        'aud is our client, no azp' => $roles,
        'azp is our client' => $roles + ['azp' => 'client-1'],
        'azp is another client' => $roles + ['azp' => 'other'],
        'azp null' => $roles + ['azp' => null],
        'azp a number' => $roles + ['azp' => 5],
        'azp a list' => $roles + ['azp' => ['client-1']],
        'aud a list of one' => $roles + ['aud' => ['client-1']],
        'two audiences, no azp' => $roles + ['aud' => ['client-1', 'account']],
        'two audiences, azp ours' => $roles + ['aud' => ['account', 'client-1'], 'azp' => 'client-1'],
        'two audiences, azp another' => $roles + ['aud' => ['account', 'client-1'], 'azp' => 'account'],
        'our client twice, no azp' => $roles + ['aud' => ['client-1', 'client-1']],
        'another audience' => $roles + ['aud' => ['account']],
        'empty audience list' => $roles + ['aud' => []],
        'no aud' => array_diff_key($roles + $idBase, ['aud' => 1]),
        'nested claim missing' => ['realm_access' => new \stdClass()],
        'no realm_access at all' => [],
        'realm_access is a string' => ['realm_access' => 'x'],
        'nested roles is a number' => ['realm_access' => ['roles' => 5]],
        'nested roles is one name' => ['realm_access' => ['roles' => 'support']],
        'nested roles null' => ['realm_access' => ['roles' => null]],
        'a top-level claim with the dotted name wins' => ['realm_access.roles' => ['support'], 'realm_access' => ['roles' => ['compliance']]],
        'a top-level dotted claim that is null falls back to the path' => ['realm_access.roles' => null] + $roles,
        'a top-level dotted claim that is empty does not' => ['realm_access.roles' => []] + $roles,
        'issued one second after the cut-off' => $roles + ['iat' => T0 + 11, 'sub' => 'erin'],
        'issued at the cut-off' => $roles + ['iat' => T0 + 10, 'sub' => 'erin'],
        'issued before the cut-off' => $roles + ['iat' => T0, 'sub' => 'erin'],
        'no iat, user revoked' => array_diff_key($roles + ['sub' => 'erin'] + $idBase, ['iat' => 1]),
        'iat a float, user revoked' => $roles + ['iat' => T0 + 11.5, 'sub' => 'erin'],
        'iat a string, user revoked' => $roles + ['iat' => (string) (T0 + 11), 'sub' => 'erin'],
        'iat true, user revoked' => $roles + ['iat' => true, 'sub' => 'erin'],
        'no iat, user not revoked' => array_diff_key($roles + $idBase, ['iat' => 1]),
    ];
    $idCfg = ['idp' => ['issuer' => 'https://idp.test', 'audience' => 'client-1', 'jwks' => ['keys' => [$idJwk]], 'groups_claim' => 'realm_access.roles']];
    $ref = new Reference('engine', Run::confConfig("$work/oidc-py", $idCfg));
    $php = new Engine(Run::confConfig("$work/oidc-php", $idCfg));
    $revoke = '{"user":"erin","now":' . (T0 + 10) . '}';
    Run::eq(masked(Json::decode($ref->ask('["revoke",' . $revoke . ']')), true), masked(Json::decode($php->callJson('revoke', $revoke)), true), 'oidc: (setup) erin is revoked in both engines');
    $okCount = 0;
    foreach ($idCases as $what => $claims) {
        $req = Json::encode(Json::fromNative(['id_token' => $signId($claims + $idBase), 'agent' => 'support-bot', 'role' => 'support-agent', 'now' => T0 + 20]));
        $a = Json::decode($php->callJson('issue_token', $req));
        $b = Json::decode($ref->ask('["issue_token",' . $req . ']'));
        $ins = '{"token":' . Json::encode($a['token'] ?? '') . ',"now":' . (T0 + 20) . '}';
        $grpA = $a['ok'] === true ? Json::encode($php->call('inspect_token', ['token' => $a['token'], 'now' => T0 + 20])['claims']['grp'] ?? null) : '';
        $grpB = $b['ok'] === true ? Json::encode(Json::decode($ref->ask('["inspect_token",{"token":' . Json::encode($b['token']) . ',"now":' . (T0 + 20) . '}]'))['claims']['grp'] ?? null) : '';
        $okCount += $a['ok'] === true ? 1 : 0;
        Run::ok(masked($a, true) === masked($b, true) && $grpA === $grpB, "oidc: same result as the reference: $what (" . ($a['ok'] === true ? "issued, grp $grpA" : $a['error']['code']) . ')',
            'php ' . masked($a, false) . " $grpA / python " . masked($b, false) . " $grpB");
    }
    Run::ok($okCount >= 6 && $okCount <= count($idCases) - 15, 'oidc: (control) the cases are a mix of issued and refused', "$okCount of " . count($idCases) . ' issued');
    $php->close();
    $ref->close();

    // the HTTP rules: the same probes against both daemons
    $mineD = new Daemon();
    $refD = new Daemon(null, 'python');
    try {
        $mine = run_probes($mineD);
        $theirs = run_probes($refD);
        foreach ($mine as $name => $got) {
            Run::ok($got === $theirs[$name] || ($got[0] === 501 && $theirs[$name][0] === 501), "e (http): same status, ok and error code as the reference daemon: $name",
                'php ' . Run::show($got) . ', python ' . Run::show($theirs[$name]));
        }
    } finally {
        $mineD->close();
        $refD->close();
    }

    // canonical JSON, byte for byte
    $canon = new Reference('canon');
    $m = 0;
    foreach (canonical_samples() as $sample) {
        $v = Json::decode($sample);
        $expected = Json::decode($canon->ask(Json::encode($v)));
        $m++;
        Run::eq($expected, Canon::canon($v), 'e: canonical form equals the reference for ' . (strlen($sample) > 80 ? substr($sample, 0, 80) . '...' : $sample));
    }
    $canon->close();
    Run::end('4. interoperability with the Python reference', "$same of $n differential steps identical ($sameText including message texts), $m canonical samples");
}

/** JSON texts whose canonical form is checked (against known answers always, against the reference when it is there). */
function canonical_samples(): array
{
    return [
        '{"b":1,"a":2}',
        '{"10":1,"9":2,"1":3,"-1":4,"08":5,"1e3":6,"":7,"0":8,"9223372036854775808":9}',
        '{"\uffff":1,"\ud83d\ude00":2,"\ue000":3,"z":4,"\u00e9":5,"e\u0301":6,"Z":7}',
        '["\u0000\u0001\u0008\u0009\u000a\u000b\u000c\u000d\u000e\u001f \u007f\u0080\u2028\u2029\ufeff"]',
        '["\"","\\\\","/","\\/","<>&","caf\u00e9","\ud83d\ude00","\u00ff\u0100"]',
        '[0,-0,1,-1,9223372036854775807,-9223372036854775808,9223372036854775808,-9223372036854775809,123456789012345678901234567890]',
        '[true,false,null,[],{},[[]],[{}],{"a":[]},{"a":{}}]',
        '[1.0,0.1,-0.0,1e16,1e15,1.5e-7,1e-5,0.0001,123456.789,1e22,5e-324,1.7976931348623157e308,2.5,1E2,100.0,0.30000000000000004]',
        '{"a":{"c":[{"z":1,"y":[{"b":1,"a":2}]}],"b":"x"},"A":1}',
        ' { "k" : [ 1 , 2 ] , "j" : "v" } ',
        '{"a":1,"a":2,"b":{"x":1},"b":{"y":2}}',
    ];
}

// ---- 5. JSON fidelity ------------------------------------------------------------------

function section_json(): void
{
    Run::begin();
    $rt = static fn (string $s): string => Json::encode(Json::decode($s));

    // (a) objects and lists are different things, in and out
    Run::ok(Json::decode('{}') instanceof JsonObject, 'a: {} decodes to a JsonObject');
    Run::ok(Json::decode('[]') === [], 'a: [] decodes to an empty list');
    Run::ok(Json::decode('{"0":"a","1":"b"}') instanceof JsonObject, 'a: {"0": "a", "1": "b"} is an object, not a list');
    $s = '{"a": {}, "b": [], "c": {"0": "x"}, "d": ["x"], "e": [{}, [], [[]], {"k": {}}], "f": {"": {}}}';
    Run::eq($s, $rt($s), 'a: {} and [] survive a round trip at every depth');
    Run::eq('{"a":{},"b":[]}', json_encode(Json::decode('{"a":{},"b":[]}')), 'a: json_encode() of the model keeps {} and []');
    Run::eq('{"0":"x"}', json_encode(Json::decode('{"0":"x"}')), 'a: json_encode() of {"0": "x"} stays an object');
    Run::ok(Json::fromNative([]) === [] && Json::fromNative(new \stdClass()) instanceof JsonObject, 'a: native []: a list; native stdClass: an object');
    Run::ok(Json::fromNative(['a' => []])['a'] === [] && Json::fromNative(['a' => (object) []])['a'] instanceof JsonObject, 'a: the same, nested');
    Run::ok(Json::fromNative([1 => 'x']) instanceof JsonObject && Json::fromNative([0 => 'x']) === ['x'], 'a: a native array with keys is an object, a native list is a list');
    Run::ok(!Json::pyEq(Json::decode('{}'), Json::decode('[]')) && !Json::pyEq(Json::decode('{"0":1}'), Json::decode('[1]')), 'a: {} is not equal to []');

    $stateDir = Run::dir('json-state');
    $e = new Engine(['bundle_dir' => Run::$bundle, 'allow_test_clock' => true, 'trust_caller_chain' => true, 'state_dir' => $stateDir]);
    $issue = '{"user":"alice","agent":"support-bot","cap":{"actions":["read","update"],"resources":["crm.customer/*"]%s},"now":' . T0 . '}';
    $out = $e->callJson('issue_token', sprintf($issue, ''));
    Run::ok(str_contains($out, '"deny_labels":[],"deny_fields":[],"budget":{}'), 'a: an issued cap is written with "deny_fields": [] and "budget": {}', $out);
    $token = Json::decode($out)['token'];
    foreach (['{}' => true, '[]' => true, '0' => true, 'null' => true, '""' => true, 'false' => true, '[1]' => false, '{"EUR":1.0}' => false,
        '{"EUR":true}' => false, '{"EUR":"1"}' => false, '{"EUR":null}' => false, '"x"' => false, '1' => false] as $budget => $accepted) {
        $r = Json::decode($e->callJson('issue_token', sprintf($issue, ',"budget":' . $budget)));
        Run::ok($accepted ? ($r['ok'] === true && $r['cap']['budget'] instanceof JsonObject && count($r['cap']['budget']) === 0) : (($r['error']['code'] ?? null) === 'invalid_cap'),
            "a/b: cap.budget $budget is " . ($accepted ? 'no budget, written back as {}' : 'invalid_cap'), Json::encode($r));
    }
    $claims = Json::decode(Tokens::b64uDec(explode('.', $token)[1]));
    Run::ok($claims['cap']['budget'] instanceof JsonObject && $claims['anc'] === [] && $claims['cap']['deny_labels'] === [], 'a: inside the token: "budget": {} and "anc": []');
    $az = '{"token":"' . $token . '","action":"read","resource":{"path":"crm.customer","id":"c-1"%s}%s,"now":' . T0 . '}';
    $code = static fn (string $json): ?string => Json::decode($json)['error']['code'] ?? null;
    Run::eq('invalid_context', $code($e->callJson('authorize', sprintf($az, '', ',"context":[]'))), 'a: context [] is not an object');
    Run::eq(null, $code($e->callJson('authorize', sprintf($az, '', ',"context":{}'))), 'a: context {} is');
    Run::eq('invalid_context', $e->call('authorize', ['token' => $token, 'action' => 'read', 'resource' => ['path' => 'crm.customer'], 'context' => [], 'now' => T0])['error']['code'] ?? null,
        'a: through call(): a native empty array is a list, so it is not a context');
    Run::eq(true, $e->call('authorize', ['token' => $token, 'action' => 'read', 'resource' => ['path' => 'crm.customer'], 'context' => new \stdClass(), 'now' => T0])['ok'],
        'a: through call(): stdClass is an empty object');
    Run::eq('invalid_input', $code($e->callJson('authorize', sprintf($az, ',"attrs":[]', ''))), 'a: resource.attrs [] is not an object');
    Run::eq(null, $code($e->callJson('authorize', sprintf($az, ',"attrs":{}', ''))), 'a: resource.attrs {} is');
    Run::eq('invalid_input', $code($e->callJson('authorize', '[]')), 'a: a request that is a list');
    Run::eq(true, $e->call('info', [])['ok'], 'a: through call(): as the request itself (and only there), a native [] is the empty object');
    Run::eq('invalid_input', $e->call('info', [[]])['error']['code'] ?? null, 'a: through call(): a non-empty native list is not a request');
    Run::eq('invalid_input', $e->call('info', 'x')['error']['code'] ?? null, 'a: through call(): a string is not a request');
    Run::eq('invalid_input', $e->call('info', fopen('php://memory', 'r'))['error']['code'] ?? null, 'a: through call(): something with no JSON form is an error, not an exception');
    $r = Json::decode($e->callJson('authorize', sprintf($az, '', ',"fields":[]')));
    Run::eq('{"allow": [], "deny": [], "redact": []}', Json::encode($r['obligations']['fields']), 'a: fields [] asks about no field; the obligation lists are []');
    $r = Json::decode($e->callJson('authorize', sprintf($az, '', ',"fields":{}')));
    Run::ok(count($r['obligations']['fields']['allow']) > 3, 'a: fields {} is not a list, so every catalogued field is decided');
    $out = $e->callJson('authorize', sprintf($az, '', ',"token":"x"'));
    Run::ok(str_contains($out, '"policies":[]') && str_contains($out, '"obligations":{}') && str_contains($out, '"principal":null'), 'a: a deny is written with "policies": [] and "obligations": {}', $out);
    $out = $e->callJson('filter', str_replace('"action":"read"', '"action":"update"', sprintf($az, '', ',"data":{}')));
    Run::ok(str_contains($out, '"data":{},"masked":[],"rows_dropped":0'), 'a: filter of data {} gives {} and "masked": []', $out);
    $out = $e->callJson('filter', sprintf($az, '', ',"data":{}'));
    Run::ok(str_contains($out, '"data":null,"masked":[],"rows_dropped":1'), 'a: under a row filter the empty record {} does not match and comes back as null', $out);
    $out = $e->callJson('filter', sprintf($az, '', ',"data":[]'));
    Run::ok(str_contains($out, '"data":[],"masked":[],"rows_dropped":0'), 'a: filter of data [] gives []', $out);
    $out = $e->callJson('filter', sprintf($az, '', ',"data":[[],{},[{"region":"EU"}]]'));
    Run::ok(str_contains($out, '"data":[],"masked":[],"rows_dropped":3'), 'a: a list is not a record: [] and [{...}] inside a list of rows are dropped, and so is {} (no region)', $out);
    $out = $e->callJson('filter', sprintf($az, '', ',"data":{"region":"EU","name":"A","addresses":[{"zip":1,"geo":2},[],{}],"e":{},"l":[]}'));
    Run::ok(str_contains($out, '"data":{"region":"EU","name":"A","addresses":[{"zip":1},[],{}]}'), 'a: nested {} and [] inside kept data stay what they were', $out);
    $out = $e->callJson('apply_obligations', '{"obligations":{"fields":{"allow":["o","l"]}},"data":{"o":{},"l":[]}}');
    Run::ok(str_contains($out, '"data":{"o":{},"l":[]},"masked":[],"rows_dropped":0'), 'a: apply_obligations keeps {} and [] apart', $out);
    Run::eq('invalid_input', $code($e->callJson('apply_obligations', '{"obligations":[],"data":{}}')), 'a: obligations [] is not an object');
    Run::eq('invalid_input', $code($e->callJson('apply_obligations', '{"obligations":{"fields":[]},"data":{}}')), 'a: obligations.fields [] is not an object');
    $shapeDir = Run::dir('json-shape');
    $se = new Engine(['bundle_dir' => Run::$bundle, 'state_dir' => $shapeDir]);
    $se->callJson('revoke', '{"token_id":"shape"}');
    $shape = (string) file_get_contents("$shapeDir/state.json");
    Run::ok(str_contains($shape, '"approvals":{},"pending":{},"ledger":{},"limits":{},"revoked_users":{}}'), 'a: state.json is written with every empty section as {} (revoked_users included), never []', $shape);
    file_put_contents("$shapeDir/state.json", '{"revoked":{}}');
    $se->callJson('revoke', '{"token_id":"shape2"}');
    $shape = (string) file_get_contents("$shapeDir/state.json");
    Run::ok(str_contains($shape, '"revoked_users":{}') && !str_contains($shape, '[]'), 'a: a state file without revoked_users is read as an empty object and written back as {}', $shape);
    file_put_contents("$shapeDir/state.json", '{"revoked_users":[]}');
    Run::eq('state_io', $code($se->callJson('info', '{}')), 'a: revoked_users [] in state.json is not an object: state_io');
    $se->close();
    $out = $e->callJson('approvals', '{}');
    Run::eq('{"pending":{},"granted":{},"ok":true}', $out, 'a: approvals with nothing pending');
    $out = $e->callJson('info', '{}');
    Run::ok(str_contains($out, '"roles":["auditor","break-glass","supervisor","support-agent"]') && str_contains($out, '"bundle_signed_by":null'), 'a: info', $out);
    $state = (string) file_get_contents("$stateDir/audit.jsonl");
    Run::ok(str_contains($state, '"masked":[]') && str_contains($state, '"obligations":{}') && str_contains($state, '"deny_fields":[]') && str_contains($state, '"budget":{}')
        && str_contains($state, '"ancestors":[]'), 'a: audit records are written with {} and [] in the right places');
    Run::ok(Cap::fromJson(Json::decode('{"budget":[]}'))->toJson()['budget'] instanceof JsonObject, 'a: Cap: budget [] reads as no budget and is written as {}');
    [$data, $masked, $dropped] = Fields::apply([], [], []);
    Run::ok($data === [] && $masked === [] && $dropped === 0, 'a: Fields: an empty list of rows');
    [$data, , $dropped] = Fields::apply(new JsonObject(), [], []);
    Run::ok($data instanceof JsonObject && $dropped === 0, 'a: Fields: an empty record');
    [$data, , $dropped] = Fields::apply(['x'], [], []);
    Run::ok($data === [] && $dropped === 1, 'a: Fields: a list is a list of rows, never a record');
    $bad = 0;
    foreach (['[]', '[{"uid":{"type":"A","id":"a"},"attrs":[1]}]', '{"x":1}'] as $i => $ents) {
        try {
            new Store(Json::decode($ents));
        } catch (CedarValueError) {
            $bad++;
        }
    }
    Run::eq(2, $bad, 'a: entities: attrs [1] and a top-level object are refused, [] is no entities');

    // (b) integers, floats, and integers beyond 64 bits
    Run::ok(Json::decode('1') === 1 && Json::decode('1.0') === 1.0 && Json::decode('1e0') === 1.0 && Json::decode('-0') === 0, 'b: 1 is an int; 1.0 and 1e0 are floats');
    Run::eq('[1, 1.0, 1.5, 100.0, 1e+16, 1e-05, -0.0, 0.1]', $rt('[1,1.0,1.5,1e2,1e16,0.00001,-0.0,0.1]'), 'b: floats are written as Python writes them, and 1.0 stays 1.0');
    Run::ok(Json::decode('9223372036854775807') === PHP_INT_MAX && Json::decode('-9223372036854775808') === PHP_INT_MIN, 'b: the 64-bit limits are ints');
    $big = Json::decode('9223372036854775808');
    Run::ok($big instanceof BigInt && $big->digits === '9223372036854775808', 'b: 2^63 is an exact BigInt, not a float and not a string');
    Run::eq('[9223372036854775808, -9223372036854775809, 123456789012345678901234567890, "9223372036854775808"]',
        $rt('[9223372036854775808,-9223372036854775809,123456789012345678901234567890,"9223372036854775808"]'), 'b: integers beyond 64 bits round-trip exactly, and stay distinct from strings');
    Run::ok(Num::add(PHP_INT_MAX, 1) instanceof BigInt && Num::str(Num::add(PHP_INT_MAX, 1)) === '9223372036854775808', 'b: Num::add does not overflow into a float');
    Run::ok(Num::sub(Num::add(PHP_INT_MAX, 900), 900) === PHP_INT_MAX && Num::sub(PHP_INT_MIN, 1) instanceof BigInt, 'b: Num::sub comes back to an int when the value fits');
    Run::ok(Num::cmp(Json::decode('99999999999999999999'), PHP_INT_MAX) > 0 && Num::cmp(Json::decode('-99999999999999999999'), PHP_INT_MIN) < 0
        && Num::cmp(Json::decode('100000000000000000000'), Json::decode('99999999999999999999')) > 0 && Num::cmp(5, 5) === 0, 'b: Num::cmp across the limit');
    Run::eq('-1', Num::str(Num::add(Json::decode('99999999999999999999'), Json::decode('-100000000000000000000'))), 'b: Num::add with mixed signs');
    Run::ok(Num::isInt(1) && Num::isInt($big) && !Num::isInt(1.0) && !Num::isInt(true) && !Num::isInt('1'), 'b: Num::isInt: not a float, not a bool, not a string');
    foreach (['1.0' => 'float', 'null' => 'null', '9223372036854775808' => 'beyond 64 bits', '{"__extn":{}}' => 'extension'] as $v => $what) {
        $threw = false;
        try {
            Cedar::fromJson(Json::decode('{"x":[' . $v . ']}'));
        } catch (CedarValueError) {
            $threw = true;
        }
        Run::ok($threw, "b: a Cedar value cannot hold a $what");
    }
    Run::eq('invalid_context', $code($e->callJson('authorize', sprintf($az, '', ',"context":{"n":1.0}'))), 'b: context 1.0 is refused');
    Run::eq(null, $code($e->callJson('authorize', sprintf($az, '', ',"context":{"n":1}'))), 'b: context 1 is accepted');
    Run::eq('invalid_context', $code($e->callJson('authorize', sprintf($az, '', ',"context":{"n":9223372036854775808}'))), 'b: context 2^63 is refused');
    Run::eq(null, $code($e->callJson('authorize', sprintf($az, '', ',"context":{"n":9223372036854775807,"m":-9223372036854775808}'))), 'b: the 64-bit limits are accepted');
    Run::eq('invalid_context', $e->call('authorize', ['token' => $token, 'action' => 'read', 'resource' => ['path' => 'crm.customer'], 'context' => ['n' => 1.0], 'now' => T0])['error']['code'] ?? null,
        'b: through call(): a PHP float in the context is refused');
    $r = Json::decode($e->callJson('issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["read"]},"ttl":1.0,"now":' . T0 . '}'));
    Run::eq(900, $r['expires_in'], 'b: ttl 1.0 is not an integer and is ignored (default 900), as in the reference');
    $r = Json::decode($e->callJson('issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["read"]},"ttl":99999999999999999999,"now":' . T0 . '}'));
    Run::eq(3600, $r['expires_in'], 'b: a ttl beyond 64 bits is an integer and is capped at max_ttl');
    $before = time();
    $r = Json::decode($e->callJson('issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["read"]},"now":1.7e9}'));
    Run::ok($r['ok'] === true && $r['expires_at'] - 900 >= $before && $r['expires_at'] - 900 <= time(), 'b: `now` 1.7e9 is a float and is not taken for the test clock');
    $out = $e->callJson('issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["read"]},"now":9223372036854775807}');
    Run::ok(str_contains($out, '"expires_at":9223372036854776707,"expires_in":900'), 'b: a clock at the 64-bit limit: expiry is computed exactly, not as a float', $out);
    $far = Json::decode($out)['token'];
    $claims = Tokens::b64uDec(explode('.', $far)[1]);
    Run::ok(str_contains($claims, '"iat":9223372036854775807,"exp":9223372036854776707,'), 'b: and written exactly into the token', $claims);
    $out = $e->callJson('inspect_token', '{"token":"' . $far . '","now":9223372036854775807}');
    Run::ok(str_contains($out, '"valid":true') && str_contains($out, '"exp":9223372036854776707') && str_contains($out, '"expires_in":900'), 'b: and read back exactly', $out);
    $out = $e->callJson('filter', sprintf($az, '', ',"data":{"region":"EU","tier":123456789012345678901234567890,"id":1.0,"name":1e16}'));
    Run::ok(str_contains($out, '"data":{"region":"EU","tier":123456789012345678901234567890,"id":1.0,"name":1e+16}'), 'b: numbers in filtered data come back as they went in', $out);
    $rows = '[{"n":1,"a":"int"},{"n":1.0,"a":"float"},{"n":true,"a":"bool"},{"n":"1","a":"str"},{"n":18446744073709551616,"a":"big"}]';
    foreach (['1' => 'int', '1.0' => 'float', 'true' => 'bool', '"1"' => 'str', '18446744073709551616' => 'big'] as $value => $kept) {
        $r = Json::decode($e->callJson('apply_obligations', '{"obligations":{"fields":{"allow":["a"]},"row_filter":[{"column":"n","op":"eq","value":' . $value . '}]},"data":' . $rows . '}'));
        Run::eq('[{"a": "' . $kept . '"}]', Json::encode($r['data']), "b: a row filter on $value keeps only the row whose value has the same type");
    }
    // Cedar longs: overflow is an evaluation error, where PHP alone would produce a float
    $ev = static function (string $expr, string $ctx = '{}'): mixed {
        $p = new Policy('p', Json::decode('{"effect":"permit","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[{"kind":"when","body":' . $expr . '}]}'));
        $r = Cedar::isAuthorized(['p' => $p], new Env(new Entity('U', 'u'), new Entity('Action', 'a'), new Entity('R', 'r'), Cedar::fromJson(Json::decode($ctx)), new Store()));
        return $r['errors'] ? 'error' : $r['decision'];
    };
    $x = '{".":{"left":{"Var":"context"},"attr":"x"}}';
    $cmp = static fn (string $l, string $r): string => '{">":{"left":' . $l . ',"right":' . $r . '}}';
    Run::eq('allow', $ev($cmp('{"+":{"left":' . $x . ',"right":{"Value":1}}}', '{"Value":0}'), '{"x":9223372036854775806}'), 'b: Cedar: max-1 + 1 is the 64-bit maximum');
    Run::eq('error', $ev($cmp('{"+":{"left":' . $x . ',"right":{"Value":1}}}', '{"Value":0}'), '{"x":9223372036854775807}'), 'b: Cedar: max + 1 overflows: an error, not a float');
    Run::eq('error', $ev($cmp('{"-":{"left":' . $x . ',"right":{"Value":1}}}', '{"Value":0}'), '{"x":-9223372036854775808}'), 'b: Cedar: min - 1 overflows');
    Run::eq('error', $ev($cmp('{"*":{"left":' . $x . ',"right":{"Value":3037000500}}}', '{"Value":0}'), '{"x":3037000500}'), 'b: Cedar: 3037000500 * 3037000500 overflows');
    Run::eq('allow', $ev($cmp('{"*":{"left":' . $x . ',"right":{"Value":3037000499}}}', '{"Value":0}'), '{"x":3037000499}'), 'b: Cedar: 3037000499 * 3037000499 does not');
    Run::eq('error', $ev($cmp('{"neg":{"arg":' . $x . '}}', '{"Value":0}'), '{"x":-9223372036854775808}'), 'b: Cedar: -(min) overflows');
    Run::eq('allow', $ev($cmp('{"neg":{"arg":' . $x . '}}', '{"Value":0}'), '{"x":-9223372036854775807}'), 'b: Cedar: -(min+1) does not');
    Run::eq('deny', $ev('{"==":{"left":' . $x . ',"right":{"Value":true}}}', '{"x":1}'), 'b: Cedar: 1 == true is false');
    Run::eq('error', $ev($cmp($x, '{"Value":0}'), '{"x":true}'), 'b: Cedar: true > 0 is a type error');
    $threw = false;
    try {
        new Policy('p', Json::decode('{"effect":"permit","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[{"kind":"when","body":{"Value":1.5}}]}'));
    } catch (\SmartDelegate\Unsupported) {
        $threw = true;
    }
    Run::ok($threw, 'b: Cedar: a float literal in a policy is refused when the bundle loads');
    $threw = false;
    try {
        new Policy('p', Json::decode('{"effect":"permit","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[{"kind":"when","body":{"Value":9223372036854775808}}]}'));
    } catch (\SmartDelegate\Unsupported) {
        $threw = true;
    }
    Run::ok($threw, 'b: Cedar: a literal beyond 64 bits is refused when the bundle loads');

    // (c) canonical JSON
    $known = [
        '{"b":1,"a":2}' => '{"a":2,"b":1}',
        '{"\uffff":1,"\ud83d\ude00":2,"\ue000":3,"z":4,"\u00e9":5}' => "{\"z\":4,\"\u{e9}\":5,\"\u{e000}\":3,\"\u{ffff}\":1,\"\u{1F600}\":2}",
        '["\u0000\u0001\u0008\u0009\u000a\u000b\u000c\u000d\u001f\u007f\u2028"]' => "[\"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f\x7f\u{2028}\"]",
        '["\"","\\\\","\/","<>&"]' => '["\"","\\\\","/","<>&"]',
        '[1,-1,0,9223372036854775807,123456789012345678901234567890,true,false,null,[],{}]' => '[1,-1,0,9223372036854775807,123456789012345678901234567890,true,false,null,[],{}]',
        ' { "k" : [ 1 , 2 ] , "j" : { } } ' => '{"j":{},"k":[1,2]}',
    ];
    foreach ($known as $in => $want) {
        Run::eq($want, Canon::canon(Json::decode($in)), "c: canonical form of $in");
    }
    Run::ok(strcmp("\u{ffff}", "\u{1F600}") < 0, 'c: UTF-8 byte order puts U+FFFF before U+1F600, which is code point order (UTF-16 order would not)');
    Run::eq(hash('sha256', '{"a":2,"b":1}'), Canon::hashValue(Json::decode('{"b":1,"a":2}')), 'c: hashValue is sha256 of the canonical text');
    Run::eq('"\u00e9\ud83d\ude00\u007f"', Json::encode("\u{e9}\u{1F600}\x7f"), 'c: the \uXXXX writer (state file, tokens) uses lowercase hex, surrogate pairs, and escapes DEL');
    Run::eq("{\n  \"a\": [\n    1,\n    {}\n  ],\n  \"b\": {},\n  \"c\": []\n}", Json::pretty(Json::decode('{"a":[1,{}],"b":{},"c":[]}')), 'c: the indented writer matches json.dumps(indent=2)');
    foreach (['[1,]', '{"a":1,}', '{a:1}', "['a']", '01', '1.', '.5', '+1', '"\x01"', '"\ud800"', '"\x"', '[1] x', '', 'nul', "\"\xff\"", '{"a" 1}', str_repeat('[', 600) . str_repeat(']', 600)] as $bad) {
        $threw = false;
        try {
            Json::decode($bad);
        } catch (JsonError) {
            $threw = true;
        }
        Run::ok($threw, 'c: not JSON: ' . (strlen($bad) > 20 ? substr($bad, 0, 20) . '...' : addcslashes($bad, "\0..\37\177..\377")));
    }
    Run::ok(is_nan(Json::decode('NaN')) && Json::decode('[Infinity,-Infinity]') === [INF, -INF] && Json::encode([NAN, INF, -INF]) === '[NaN, Infinity, -Infinity]',
        'c: NaN and Infinity are read and written as Python does');
    Run::eq("a\u{1F600}/\u{e9}", Json::decode('"a\ud83d\ude00\/\u00e9"'), 'c: escapes and surrogate pairs decode');
    Run::eq(2, Json::decode('{"a":1,"a":2}')['a'], 'c: a repeated key: the last value wins');

    // (d) numeric string keys
    $o = Json::decode('{"10":"a","9":"b","-5":"c","08":"d","1e3":"e","0":"f","9223372036854775808":"g"}');
    Run::ok($o->keys() === ['10', '9', '-5', '08', '1e3', '0', '9223372036854775808'], 'd: keys come back as strings, in order', Run::show($o->keys()));
    $allStrings = true;
    foreach ($o as $k => $_) {
        $allStrings = $allStrings && is_string($k);
    }
    Run::ok($allStrings && $o->has('10') && $o['9'] === 'b' && $o->get('-5') === 'c', 'd: iteration yields string keys; lookups by string work');
    Run::eq('{"-5":"c","0":"f","08":"d","10":"a","1e3":"e","9":"b","9223372036854775808":"g"}', Canon::canon($o), 'd: canonical order is string order ("10" before "9"), not numeric order');
    Run::eq('{"10": "a", "9": "b", "-5": "c", "08": "d", "1e3": "e", "0": "f", "9223372036854775808": "g"}', Json::encode($o), 'd: and they are written back as strings in the original order');
    Run::eq('{"7":{"3":[{"5":1}]}}', Json::compact(Json::fromNative([7 => [3 => [[5 => 1]]]])), 'd: native integer keys become string keys');
    $out = $e->callJson('apply_obligations', '{"obligations":{"fields":{"allow":["10","2","0"],"deny":["9"]}},"data":[{"10":"a","9":"b","2":"c","0":"d","1":"e"}]}');
    Run::ok(str_contains($out, '"data":[{"10":"a","2":"c","0":"d"}],"masked":["1","9"]'), 'd: field names that look like numbers are masked and sorted as strings', $out);
    $out = $e->callJson('apply_obligations', '{"obligations":{"fields":{"allow":["0"]},"row_filter":[{"column":"0","op":"eq","value":"x"}]},"data":[{"0":"x"},{"0":"y"}]}');
    Run::ok(str_contains($out, '"data":[{"0":"x"}],"masked":[],"rows_dropped":1'), 'd: a record {"0": ...} is a record, not a list', $out);
    $r = Json::decode($e->callJson('issue_token', '{"user":"alice","agent":"support-bot","cap":{"actions":["read"],"budget":{"840":5,"978":7}},"now":' . T0 . '}'));
    Run::eq('{"840": 5, "978": 7}', Json::encode($r['cap']['budget']), 'd: numeric currency codes stay string keys of an object');
    $e->callJson('revoke', '{"token_id":"123"}');
    $e->callJson('revoke', '{"token_id":"0"}');
    $e->call('revoke', ['token' => $token]);
    $state = (string) file_get_contents("$stateDir/state.json");
    Run::ok(preg_match('/"revoked":\{"123":\d+,"0":\d+,"[0-9a-f]{24}":\d+\}/', $state) === 1 && str_contains($state, '"limits":{"' . $r['token_id'] . '":{"840":5,"978":7}}'), 'd: state.json keeps "123" and "0" as string keys of an object', $state);
    $e->close();
    $e2 = new Engine(['bundle_dir' => Run::$bundle, 'state_dir' => $stateDir, 'allow_test_clock' => true]);
    Run::eq('token_revoked', $e2->call('inspect_token', ['token' => $token, 'now' => T0])['reason'] ?? 'valid', 'd: (control) a new engine reads that state file back');
    $e2->call('revoke', ['token_id' => '7']);
    Run::ok(preg_match('/"revoked":\{"123":\d+,"0":\d+,"[0-9a-f]{24}":\d+,"7":\d+\}/', (string) file_get_contents("$stateDir/state.json")) === 1,
        'd: and writes it back with the same string keys in the same order', (string) file_get_contents("$stateDir/state.json"));
    $e2->close();
    $p = [];
    foreach (['10', '9', '2'] as $pid) {
        $p[$pid] = new Policy($pid, Json::decode('{"effect":"permit","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"}}'));
    }
    $r = Cedar::isAuthorized($p, new Env(new Entity('U', 'u'), new Entity('Action', 'a'), new Entity('R', 'r'), [], new Store()));
    Run::ok($r['reasons'] === ['10', '2', '9'], 'd: policy ids that look like numbers are reported as strings in string order', Run::show($r['reasons']));
    $set = Cedar::fromJson(Json::decode('{"r":{"1":1,"01":2},"s":[1,"1",true,1]}'));
    Run::ok(count($set['s']->items) === 3 && Cedar::key($set['r']) !== Cedar::key(Cedar::fromJson(Json::decode('{"1":2,"01":1}'))), 'd: Cedar sets and records tell 1, "1" and true apart');

    Run::end('5. JSON fidelity');
}

// ---- 6. the front controller under `php -S` ------------------------------------------------

function section_front_controller(): void
{
    Run::begin();
    $n = $passed = 0;
    $documented = [];
    foreach (all_cases() as [$suite, $case, $config]) {
        $d = new Daemon($config, 'builtin');
        try {
            $r = Conformance::runCase([$d->client(), 'call'], $case);
        } finally {
            $d->close();
        }
        $n++;
        // The one thing that cannot work with a fresh engine per request: rate-limit windows are kept in
        // engine memory (in the reference too). A case that expects `rate_limited` is reported, not counted.
        $needsMemory = str_contains(Json::encode($case), '"rate_limited"');
        if ($needsMemory) {
            $documented[] = Run::show($r['name']) . ($r['passed'] ? ' (passed)' : ' (differs, as documented)');
            Run::ok(!$r['passed'], 'front controller: a case that needs in-memory rate-limit state is expected to differ: ' . Run::show($r['name']),
                'it passed; the README section "Under php-fpm" is out of date');
            continue;
        }
        $passed += $r['passed'] ? 1 : 0;
        Run::ok($r['passed'], "$suite via public/index.php: " . Run::show($r['name']), $r['passed'] ? '' : json_encode($r['failures']));
    }
    $d = new Daemon(null, 'builtin');
    try {
        // decided by the web server in front of PHP, not by index.php (`php -S` waits for a declared body that never comes)
        $notHere = ['bad Content-Length', 'a body over 8 MiB is refused unread', 'the path is not normalised'];
        $got = run_probes($d, $notHere);
        foreach (http_probes() as [$name, , , , , $status, $code]) {
            if (in_array($name, $notHere, true)) {
                continue;
            }
            Run::ok($got[$name][0] === $status && ($status === 501 || $got[$name][2] === $code), "front controller http: $name",
                "expected $status " . Run::show($code) . ', got ' . Run::show($got[$name]));
        }
        // what does work across requests: everything kept in the state directory
        $c = $d->client();
        $before = $c->call('audit_verify')['records'] ?? -1;
        $t = $c->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => ['actions' => ['create'], 'resources' => ['billing.refund/*'], 'budget' => ['EUR' => 10000]]]);
        $spend = ['token' => $t['token'], 'action' => 'create', 'resource' => ['path' => 'billing.refund', 'id' => 'r'], 'context' => ['spend' => ['currency' => 'EUR', 'amount' => 4000]]];
        $r1 = $c->call('authorize', $spend);
        $r2 = $c->call('authorize', $spend);
        $r3 = $c->call('authorize', $spend);
        Run::ok($r1['effect'] === 'allow' && $r2['effect'] === 'allow' && $r3['reason'] === 'budget_exceeded', 'front controller: spend is counted across requests (state.json)');
        Run::ok(($r1['obligations']['rate_limit']['used'] ?? null) === 0 && ($r2['obligations']['rate_limit']['used'] ?? null) === 0,
            'front controller: the rate-limit counter starts at 0 on every request (documented: it is per process)');
        $c->call('revoke', ['token_id' => $t['token_id']]);
        Run::eq('token_revoked', $c->call('authorize', $spend)['reason'] ?? null, 'front controller: a revocation holds across requests');
        $v = $c->call('audit_verify', []);
        Run::ok($v['ok'] === true && $v['records'] === $before + 6, 'front controller: one valid audit chain across requests (6 more records)', "before $before, now " . Run::show($v));
    } finally {
        $d->close();
    }
    $bad = new Daemon(null, 'builtin');
    file_put_contents($bad->config, '{"bundle_dir": "/nonexistent", "admin_key": "' . Daemon::ADMIN . '", "pep_key": "' . Daemon::PEP . '"}');
    [$status, $text] = $bad->http('GET', '/healthz');
    Run::ok($status === 500 && !str_contains($text, 'nonexistent'), 'front controller: a broken configuration is a 500 that does not leak paths', "$status $text");
    $bad->close();
    Run::end('6. front controller (public/index.php under php -S)', "$passed of " . ($n - count($documented)) . ' cases pass; ' . count($documented)
        . ' not counted: ' . implode(', ', $documented));
}

// ---- 7. keys, ID tokens, failing closed --------------------------------------------------

/** DER SEQUENCE { INTEGER r, INTEGER s } -> r || s, each `size` bytes (what a JWS carries). */
function der_to_raw(string $der, int $size): string
{
    $i = 2 + (ord($der[1]) & 0x80 ? ord($der[1]) & 0x7f : 0);
    $out = '';
    for ($k = 0; $k < 2; $k++) {
        $len = ord($der[$i + 1]);
        $out .= str_pad(ltrim(substr($der, $i + 2, $len), "\0"), $size, "\0", STR_PAD_LEFT);
        $i += 2 + $len;
    }
    return $out;
}

/** @return array{string,JsonObject} a signed ID token and the JWK that verifies it */
function make_id_token(string $alg, array $claims, string $kid): array
{
    $head = Tokens::b64u(Json::compact(Json::fromNative(['alg' => $alg, 'typ' => 'JWT', 'kid' => $kid])));
    $body = Tokens::b64u(Json::compact(Json::fromNative($claims)));
    $input = "$head.$body";
    if ($alg === 'EdDSA') {
        $pair = sodium_crypto_sign_keypair();
        $sig = sodium_crypto_sign_detached($input, sodium_crypto_sign_secretkey($pair));
        $jwk = ['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => $kid, 'x' => Tokens::b64u(sodium_crypto_sign_publickey($pair))];
    } elseif ($alg[0] === 'R') {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        openssl_sign($input, $sig, $key, 'sha' . substr($alg, 2));
        $d = openssl_pkey_get_details($key)['rsa'];
        $jwk = ['kty' => 'RSA', 'kid' => $kid, 'n' => Tokens::b64u($d['n']), 'e' => Tokens::b64u($d['e'])];
    } else {
        [$curve, $size] = $alg === 'ES256' ? ['prime256v1', 32] : ['secp384r1', 48];
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
        openssl_sign($input, $der, $key, 'sha' . substr($alg, 2));
        $sig = der_to_raw($der, $size);
        $d = openssl_pkey_get_details($key)['ec'];
        $jwk = ['kty' => 'EC', 'crv' => $alg === 'ES256' ? 'P-256' : 'P-384', 'kid' => $kid, 'x' => Tokens::b64u($d['x']), 'y' => Tokens::b64u($d['y'])];
    }
    return ["$input." . Tokens::b64u($sig), Json::fromNative($jwk)];
}

function section_keys(): void
{
    Run::begin();
    // Ed25519 and the key formats: RFC 8032, section 7.1, test 1
    $seed = hex2bin('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    $pk8 = base64_encode(hex2bin('302e020100300506032b657004220420') . $seed);
    [$secret, $public] = Bundle::loadPrivate($pk8 . "\n");
    Run::eq('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', bin2hex($public), 'keys: PKCS#8 seed -> the RFC 8032 public key');
    Run::eq('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
        bin2hex(sodium_crypto_sign_detached('', $secret)), 'keys: and the RFC 8032 signature');
    Run::eq(substr(hash('sha256', $public), 0, 16), Bundle::keyId(base64_encode($public)), 'keys: key id is the first 16 hex characters of sha256(public key)');
    [$sk, $pk] = Bundle::keygen();
    $der = base64_decode($sk, true);
    Run::ok(strlen($der) === 48 && bin2hex(substr($der, 0, 16)) === '302e020100300506032b657004220420' && strlen(base64_decode($pk, true)) === 32,
        'keys: a generated private key is the 48-byte PKCS#8 v1 DER, the public key 32 raw bytes');
    Run::eq($pk, base64_encode(Bundle::loadPrivate($sk)[1]), 'keys: and they belong together');
    foreach (['', 'AAAA', substr($sk, 0, -4), $sk . 'AAAA', base64_encode(str_repeat('x', 48)), '!' . substr($sk, 1), $pk] as $i => $bad) {
        $code = '';
        try {
            Bundle::loadPrivate($bad);
        } catch (EngineError $e) {
            $code = $e->errorCode;
        }
        Run::eq('crypto', $code, "keys: malformed private key #$i is refused");
    }
    foreach (['', 'AAAA', $sk, substr($pk, 0, -1), rtrim($pk, '=')] as $i => $bad) {
        $code = '';
        try {
            Bundle::loadPublic($bad);
        } catch (EngineError $e) {
            $code = $e->errorCode;
        }
        Run::eq('crypto', $code, "keys: malformed public key #$i is refused");
    }
    $state = Run::dir('keys-state');
    $e = new Engine(['bundle_dir' => Run::$bundle, 'state_dir' => $state]);
    $info = $e->call('info');
    Run::ok(trim((string) file_get_contents("$state/signing_key.pub.b64")) === $info['public_key'] && substr(sprintf('%o', fileperms("$state/signing_key.pk8.b64")), -4) === '0600',
        'keys: the engine writes its key pair to the state directory, the private key with mode 0600');
    $e->close();
    $e = new Engine(['bundle_dir' => Run::$bundle, 'state_dir' => $state]);
    Run::eq($info['key_id'], $e->call('info')['key_id'], 'keys: and uses the same key the next time');
    $e->close();
    $e = new Engine(['bundle_dir' => Run::$bundle, 'signing_key' => $pk8, 'allow_test_clock' => true]);
    Run::eq(base64_encode($public), $e->call('info')['public_key'], 'keys: `signing_key` in the configuration is used as given');
    // capability tokens: the checks of PORTING.md, in order
    $t = $e->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => ['actions' => ['read'], 'resources' => ['crm.customer/*']], 'now' => T0])['token'];
    [$h, $b, $sg] = explode('.', $t);
    $why = static fn (string $token): string => (string) ($e->call('inspect_token', ['token' => $token, 'now' => T0])['detail'] ?? 'valid');
    $resign = static function (array $header, mixed $claims) use ($secret): string {
        $hh = Tokens::b64u(Json::compact(Json::fromNative($header)));
        $bb = Tokens::b64u(is_string($claims) ? $claims : Json::compact(Json::fromNative($claims)));
        return "$hh.$bb." . Tokens::b64u(sodium_crypto_sign_detached("$hh.$bb", $secret));
    };
    $kid = $e->call('info')['key_id'];
    $good = ['iss' => 'smartdelegate://local', 'aud' => 'smartdelegate', 'sub' => 'user:alice', 'iat' => T0, 'exp' => T0 + 60, 'jti' => 'j1',
        'act' => ['sub' => 'agent:support-bot'], 'cap' => ['actions' => ['read']]];
    $hd = ['typ' => 'JWT', 'alg' => 'EdDSA', 'kid' => $kid];
    Run::eq('valid', $why($t), 'token: an issued token verifies');
    Run::eq('valid', $why($resign($hd, $good)), 'token: a hand-built token with the minimal claims verifies (anc defaults to [])');
    Run::eq('token is not a JWT', $why("$h.$b"), 'token: two parts');
    Run::eq('token is not a JWT', $why("$h.$b.$sg.x"), 'token: four parts');
    Run::eq('token is not a JWT', $why("$h.$b.$sg="), 'token: padding');
    Run::eq('token is not a JWT', $why("$h.$b."), 'token: empty signature part');
    Run::eq('token is not a JWT', $why(Tokens::b64u('not json') . ".$b.$sg"), 'token: header that is not JSON');
    Run::eq('token algorithm is not EdDSA', $why($resign(['typ' => 'JWT', 'alg' => 'none', 'kid' => $kid], $good)), 'token: alg none');
    Run::eq('token algorithm is not EdDSA', $why($resign(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => $kid], $good)), 'token: alg HS256');
    Run::eq('token algorithm is not EdDSA', $why(Tokens::b64u('[]') . ".$b.$sg"), 'token: header that is a list');
    Run::eq('token has no key id', $why($resign(['typ' => 'JWT', 'alg' => 'EdDSA'], $good)), 'token: no kid');
    Run::eq('token was signed by an unknown key', $why($resign(['typ' => 'JWT', 'alg' => 'EdDSA', 'kid' => '0000000000000000'], $good)), 'token: unknown kid');
    Run::eq('token rejected: bad signature', $why("$h.$b." . Tokens::b64u(str_repeat("\0", 64))), 'token: wrong signature');
    Run::eq('token rejected: bad signature', $why("$h.$b." . Tokens::b64u('short')), 'token: short signature');
    Run::eq('token rejected: bad signature', $why("$h." . Tokens::b64u(str_replace('alice', 'carol', Tokens::b64uDec($b))) . ".$sg"), 'token: changed claims');
    foreach ([['iss', 5], ['aud', null], ['sub', ['x']], ['jti', 1], ['iat', 1.5], ['iat', '1'], ['exp', true], ['exp', 1.7e9], ['act', 'agent:x'], ['act', []], ['anc', 'x'],
        ['anc', [1]], ['role', ''], ['role', 5], ['role', null], ['grp', 'g'], ['grp', [['type' => 'Group']]], ['grp', ['g']], ['cap', []], ['cap', ['x' => 1]],
        ['cap', ['budget' => ['EUR' => 1.0]]], ['cap', null]] as [$k, $v]) {
        Run::eq('token rejected: malformed claims', $why($resign($hd, [$k => $v] + $good)), "token: claim $k = " . Run::show($v));
    }
    foreach (['iss', 'aud', 'sub', 'jti', 'iat', 'exp', 'act', 'cap'] as $k) {
        Run::eq('token rejected: malformed claims', $why($resign($hd, array_diff_key($good, [$k => 1]))), "token: no $k claim");
    }
    Run::eq('token rejected: malformed claims', $why($resign($hd, '[1]')), 'token: claims that are a list');
    Run::eq('token rejected: malformed claims', $why($resign($hd, '{"iss":')), 'token: claims that are not JSON');
    Run::eq('token rejected: wrong audience', $why($resign($hd, ['aud' => 'other'] + $good)), 'token: wrong audience');
    Run::eq('token rejected: wrong issuer', $why($resign($hd, ['iss' => 'other'] + $good)), 'token: wrong issuer');
    Run::eq('the token names no agent', $why($resign($hd, ['act' => new \stdClass()] + $good)), 'token: no agent');
    Run::eq('the capability token has expired', $why($resign($hd, ['exp' => T0] + $good)), 'token: expires exactly now');
    Run::eq('the capability token is dated in the future', $why($resign($hd, ['iat' => T0 + 61, 'exp' => T0 + 90] + $good)), 'token: issued more than 60 s ahead');
    Run::eq('valid', $why($resign($hd, ['iat' => T0 + 60, 'exp' => T0 + 90] + $good)), 'token: issued exactly 60 s ahead is tolerated');
    $e->close();

    // OIDC ID tokens: every algorithm the reference accepts
    $python = python_available() === null;
    $claims = ['iss' => 'https://idp.test', 'aud' => 'client-1', 'sub' => 'alice', 'iat' => T0, 'exp' => T0 + 600, 'groups' => ['support']];
    $work = Run::dir('oidc');
    foreach (['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'EdDSA'] as $alg) {
        $rounds = $alg[0] === 'E' && $alg !== 'EdDSA' ? 12 : 1;   // ECDSA: several signatures, so r and s with and without a leading zero bit occur
        $allOk = true;
        for ($i = 0; $i < $rounds; $i++) {
            [$idt, $jwk] = make_id_token($alg, $claims, "k-$alg");
            $cfg = ['bundle_dir' => Run::$bundle, 'allow_test_clock' => true,
                'idp' => ['issuer' => 'https://idp.test', 'audience' => 'client-1', 'jwks' => ['keys' => [$jwk]], 'groups_claim' => 'groups']];
            $eng = new Engine($cfg);
            $r = $eng->call('issue_token', ['id_token' => $idt, 'agent' => 'support-bot', 'role' => 'support-agent', 'now' => T0]);
            $allOk = $allOk && $r['ok'] === true && $r['user'] === 'alice' && $r['role'] === 'support-agent';
            if ($i === 0) {
                [$hh, $bb, $ss] = explode('.', $idt);
                $raw = Tokens::b64uDec($ss);
                $raw[strlen($raw) - 1] = chr(ord($raw[strlen($raw) - 1]) ^ 1);
                $bad = $eng->call('issue_token', ['id_token' => "$hh.$bb." . Tokens::b64u($raw), 'agent' => 'support-bot', 'role' => 'support-agent', 'now' => T0]);
                Run::eq('id_token_invalid', $bad['error']['code'] ?? null, "oidc: $alg: a signature with one bit flipped is refused");
                $bad = $eng->call('issue_token', ['id_token' => "$hh." . Tokens::b64u(str_replace('alice', 'carol', Tokens::b64uDec($bb))) . ".$ss", 'agent' => 'support-bot', 'cap' => ['actions' => ['read']], 'now' => T0]);
                Run::eq('id_token_invalid', $bad['error']['code'] ?? null, "oidc: $alg: changed claims are refused");
                $bad = $eng->call('issue_token', ['id_token' => "$hh.$bb." . Tokens::b64u(substr(Tokens::b64uDec($ss), 1)), 'agent' => 'support-bot', 'cap' => ['actions' => ['read']], 'now' => T0]);
                Run::eq('id_token_invalid', $bad['error']['code'] ?? null, "oidc: $alg: a signature of the wrong length is refused");
                Run::eq('id_token_invalid', $eng->call('issue_token', ['id_token' => $idt, 'agent' => 'support-bot', 'cap' => ['actions' => ['read']], 'now' => T0 + 600])['error']['code'] ?? null,
                    "oidc: $alg: expired at exp");
                foreach (['RS256', 'ES256', 'ES384', 'EdDSA', 'HS256', 'none'] as $other) {
                    if ($other !== $alg && !($alg[0] === 'R' && $other === 'RS256')) {
                        $forged = Tokens::b64u(Json::compact(Json::fromNative(['alg' => $other, 'kid' => "k-$alg"]))) . ".$bb.$ss";
                        $allOk = $allOk && ($eng->call('issue_token', ['id_token' => $forged, 'agent' => 'support-bot', 'cap' => ['actions' => ['read']], 'now' => T0])['error']['code'] ?? null) === 'id_token_invalid';
                    }
                }
                if ($python) {
                    $cfgFile = Run::writeJson("$work/$alg.json", $cfg);
                    [$code, $out, $err] = Run::py(['call', 'issue_token', '--config', $cfgFile, '--input',
                        Json::encode(Json::fromNative(['id_token' => $idt, 'agent' => 'support-bot', 'role' => 'support-agent', 'now' => T0]))]);
                    Run::ok($code === 0 && Json::decode($out)['user'] === 'alice', "oidc: $alg: the Python reference accepts the same ID token and key", $out . $err);
                }
            }
            $eng->close();
        }
        Run::ok($allOk, "oidc: $alg ID token is verified ($rounds signature" . ($rounds > 1 ? 's' : '') . '); the same token under another alg is refused');
    }
    if (!$python) {
        Run::note('   (oidc: the cross-check of these ID tokens against the Python reference was skipped: ' . python_available() . ')');
    }

    // reload re-reads idp.jwks_file: a key rotation needs a reload, not a restart; a file that fails to load
    // leaves the old keys AND the old bundle in force
    $rot = Run::dir('rotate');
    Run::copyDir(Run::$bundle, "$rot/bundle");
    $mk = static function (string $kid): array {
        $pair = sodium_crypto_sign_keypair();
        $jwk = ['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => $kid, 'x' => Tokens::b64u(sodium_crypto_sign_publickey($pair))];
        $h = Tokens::b64u(Json::compact(Json::fromNative(['alg' => 'EdDSA', 'kid' => $kid])));
        $b = Tokens::b64u(Json::compact(Json::fromNative(['iss' => 'https://idp.test', 'aud' => 'client-1', 'sub' => 'alice', 'iat' => T0, 'exp' => T0 + 600])));
        return [$jwk, "$h.$b." . Tokens::b64u(sodium_crypto_sign_detached("$h.$b", sodium_crypto_sign_secretkey($pair)))];
    };
    [$jwkA, $tokA] = $mk('a');
    [$jwkB, $tokB] = $mk('b');
    Run::writeJson("$rot/jwks.json", ['keys' => [$jwkA]]);
    $re = new Engine(['bundle_dir' => "$rot/bundle", 'state_dir' => "$rot/state", 'allow_test_clock' => true,
        'idp' => ['issuer' => 'https://idp.test', 'audience' => 'client-1', 'jwks_file' => "$rot/jwks.json"]]);
    $try = static fn (string $t): string => (string) (($r = $re->call('issue_token', ['id_token' => $t, 'agent' => 'support-bot', 'cap' => ['actions' => ['read']], 'now' => T0]))['ok'] === true ? 'issued' : $r['error']['code']);
    Run::eq(['issued', 'id_token_invalid'], [$try($tokA), $try($tokB)], 'reload: (control) the engine knows key a, not key b');
    Run::writeJson("$rot/jwks.json", ['keys' => [$jwkB]]);
    Run::eq(['issued', 'id_token_invalid'], [$try($tokA), $try($tokB)], 'reload: a changed jwks_file has no effect until reload');
    Run::eq(true, $re->call('reload')['ok'], 'reload: reload succeeds');
    Run::eq(['id_token_invalid', 'issued'], [$try($tokA), $try($tokB)], 'reload: after reload the new key is accepted and the retired one is not');
    $v0 = $re->call('info')['policy_version'];
    foreach (['not JSON' => '{"keys": [', 'a list' => '[]', 'no keys' => '{}', 'keys not a list' => '{"keys": {}}', 'not UTF-8' => "{\"keys\": [\"\xff\"]}", 'a byte order mark' => "\xEF\xBB\xBF{\"keys\": []}"] as $what => $text) {
        file_put_contents("$rot/jwks.json", $text);
        Run::eq('invalid_config', $re->call('reload')['error']['code'] ?? null, "reload: a jwks_file that is $what is invalid_config");
    }
    unlink("$rot/jwks.json");
    Run::eq('invalid_config', $re->call('reload')['error']['code'] ?? null, 'reload: a missing jwks_file is invalid_config');
    Run::eq(['id_token_invalid', 'issued'], [$try($tokA), $try($tokB)], 'reload: and the old keys stay in force');
    // a broken JWKS also keeps the old bundle, although the new bundle itself would load
    file_put_contents("$rot/bundle/entities.json", str_replace('"region": "EU"', '"region": "UK"', (string) file_get_contents("$rot/bundle/entities.json")));
    file_put_contents("$rot/jwks.json", '[]');
    Run::eq('invalid_config', $re->call('reload')['error']['code'] ?? null, 'reload: new bundle + broken jwks_file is refused');
    Run::eq($v0, $re->call('info')['policy_version'], 'reload: and the old bundle stays in force too');
    // a broken bundle keeps the old keys, although the new JWKS would load
    Run::writeJson("$rot/jwks.json", ['keys' => [$jwkA]]);
    file_put_contents("$rot/bundle/roles.json", '{"roles": []}');
    Run::eq('roles_parse', $re->call('reload')['error']['code'] ?? null, 'reload: broken bundle + new jwks_file is refused');
    Run::eq(['id_token_invalid', 'issued', $v0], [$try($tokA), $try($tokB), $re->call('info')['policy_version']], 'reload: and neither keys nor bundle were replaced');
    copy(Run::$bundle . '/roles.json', "$rot/bundle/roles.json");
    Run::eq(true, $re->call('reload')['ok'], 'reload: with both in order, reload succeeds');
    Run::ok($try($tokA) === 'issued' && $try($tokB) === 'id_token_invalid' && $re->call('info')['policy_version'] !== $v0, 'reload: and both the keys and the bundle are the new ones');
    $re->close();
    $inl = new Engine(['bundle_dir' => Run::$bundle, 'allow_test_clock' => true, 'idp' => ['issuer' => 'https://idp.test', 'audience' => 'client-1', 'jwks' => ['keys' => [$jwkA]], 'jwks_file' => "$rot/nope.json"]]);
    Run::eq(true, $inl->call('reload')['ok'], 'reload: inline keys are not re-read from a jwks_file that is also named');
    $inl->close();

    // failing closed
    $state = Run::dir('closed-state');
    $cap = ['actions' => ['read'], 'resources' => ['crm.customer/*'], 'budget' => ['EUR' => 5]];
    $e = new Engine(Run::confConfig($state));
    $t = $e->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => $cap, 'now' => T0])['token'];
    $req = ['token' => $t, 'action' => 'read', 'resource' => ['path' => 'crm.customer', 'id' => 'c-1'], 'now' => T0];
    Run::eq('allow', $e->call('authorize', $req)['effect'] ?? null, 'closed: (control) the request is allowed');
    rename("$state/audit.jsonl", "$state/audit.keep");
    mkdir("$state/audit.jsonl");
    $r = $e->call('authorize', $req);
    Run::ok($r['ok'] === false && in_array($r['error']['code'], ['audit_io', 'audit_broken'], true), 'closed: when the audit log cannot be written, the request is refused', Run::show($r));
    rmdir("$state/audit.jsonl");
    file_put_contents("$state/audit.jsonl", '');
    Run::eq('audit_io', $e->call('authorize', $req)['error']['code'] ?? null, 'closed: an audit log truncated while in use refuses the request');
    rename("$state/audit.keep", "$state/audit.jsonl");
    Run::eq('allow', $e->call('authorize', $req)['effect'] ?? null, 'closed: (control) with the log restored it is allowed again');
    $saved = (string) file_get_contents("$state/state.json");
    foreach (['{"revoked":', '[]', '{"revoked":[]}', "\xff\xfe"] as $i => $corrupt) {
        file_put_contents("$state/state.json", $corrupt);
        Run::eq('state_io', $e->call('authorize', $req)['error']['code'] ?? null, "closed: a corrupt state file (#$i) refuses the request");
    }
    file_put_contents("$state/state.json", $saved);
    Run::eq('allow', $e->call('authorize', $req)['effect'] ?? null, 'closed: (control) with the state restored it is allowed again');
    $threw = '';
    foreach ([[], 'x', null, 5, ['a'], new \DateTime(), fopen('php://memory', 'r'), NAN, ["\xff" => 1], ['token' => "\xff"]] as $payload) {
        foreach (['authorize', 'filter', 'explain', 'issue_token', 'exchange_token', 'inspect_token', 'apply_obligations', 'revoke', 'approve', 'approvals',
            'audit_verify', 'audit_tail', 'info', '', "\0", 'nonsense'] as $op) {
            try {
                $r = $e->call($op, $payload);
                if (!is_bool($r['ok'] ?? null) || ($r['ok'] === false && !is_string($r['error']['code'] ?? null)) || ($r['effect'] ?? 'deny') === 'allow') {
                    $threw .= " $op:" . Run::show($r);
                }
            } catch (\Throwable $ex) {
                $threw .= " $op:" . get_class($ex);
            }
        }
    }
    Run::eq('', $threw, 'closed: call() never throws and never allows on malformed input (10 payloads x 16 operations)');
    $deep = [];
    $cur = &$deep;
    for ($i = 0; $i < 5000; $i++) {
        $cur['x'] = [];
        $cur = &$cur['x'];
    }
    unset($cur);
    Run::eq('invalid_input', $e->call('authorize', ['action' => 'read', 'resource' => ['path' => 'crm.customer'], 'context' => $deep])['error']['code'] ?? null,
        'closed: a request nested 5000 deep is refused, not a crash');
    Run::ok(str_contains($e->callJson('authorize', str_repeat('[', 5000) . str_repeat(']', 5000)), '"invalid_input"'), 'closed: the same as JSON text');
    Run::ok(str_contains($e->callJson('authorize', '{"action":'), '"invalid_input"'), 'closed: callJson with text that is not JSON');
    $e->close();

    // bundles that must not load, and reload keeping the old one
    $b = "$work/bundle";
    Run::copyDir(Run::$bundle, $b);
    $load = static function () use ($b): string {
        try {
            (new Engine(['bundle_dir' => $b]))->close();
            return 'loaded';
        } catch (EngineError $e) {
            return $e->errorCode;
        }
    };
    Run::eq('loaded', $load(), 'bundle: (control) the copy loads');
    $e = new Engine(['bundle_dir' => $b, 'state_dir' => Run::dir('reload-state')]);
    $version = $e->call('info')['policy_version'];
    $edit = static function (string $file, callable $change) use ($b, $load): string {
        $orig = (string) file_get_contents("$b/$file");
        file_put_contents("$b/$file", $change($orig));
        $r = $load();
        file_put_contents("$b/$file", $orig);
        return $r;
    };
    file_put_contents("$b/policies/crm.cedar", file_get_contents("$b/policies/crm.cedar") . "\n// edited\n");
    Run::eq('bundle_stale', $load(), 'bundle: a .cedar source edited without recompiling');
    Run::eq('bundle_stale', $e->call('reload')['error']['code'] ?? null, 'bundle: reload refuses it');
    Run::ok($e->call('info')['policy_version'] === $version && $e->call('info')['policies'] === 21, 'bundle: and the old bundle stays in force');
    copy(Run::$bundle . '/policies/crm.cedar', "$b/policies/crm.cedar");
    file_put_contents("$b/policies/new.cedar", "permit(principal, action, resource);\n");
    Run::eq('bundle_stale', $load(), 'bundle: a .cedar source added without recompiling');
    unlink("$b/policies/new.cedar");
    Run::eq('loaded', $load(), 'bundle: (control) restored');
    Run::eq('policy_parse', $edit('policies.json', static fn (string $s): string => substr($s, 0, -5)), 'bundle: policies.json that is not JSON');
    Run::eq('policy_parse', $edit('policies.json', static fn (string $s): string => '{"policies": []}'), 'bundle: policies as a list');
    Run::eq('policy_parse', $edit('policies.json', static fn (string $s): string => '[]'), 'bundle: policies.json as a list');
    Run::eq('policy_parse', $edit('policies.json', static fn (string $s): string => preg_replace('/"effect":\s*"permit"/', '"effect":"allow"', $s, 1)), 'bundle: an unknown effect');
    Run::eq('policy_parse', $edit('policies.json', static fn (string $s): string => preg_replace('/\{\s*"Var":\s*"context"\s*\}/', '{"ip":[{"Value":"10.0.0.1"}]}', $s, 1)), 'bundle: an extension function (ip)');
    Run::eq('policy_parse', $edit('policies.json', static fn (string $s): string => preg_replace('/\{\s*"Var":\s*"context"\s*\}/', '{"Value":1.5}', $s, 1)), 'bundle: a float literal');
    Run::eq('policy_parse', $edit('policies.json', static fn (string $s): string => preg_replace('/\{\s*"Var":\s*"context"\s*\}/', '{"Var":"env"}', $s, 1)), 'bundle: an unknown variable');
    Run::eq('entities_parse', $edit('entities.json', static fn (string $s): string => '{"x": 1}'), 'bundle: entities.json as an object');
    Run::eq('entities_parse', $edit('entities.json', static fn (string $s): string => str_replace('{"region": "EU"}', '{"region": 1.5}', $s)), 'bundle: a float attribute');
    Run::eq('entities_parse', $edit('entities.json', static fn (string $s): string => str_replace('"attrs": {"region": "US"}, "parents": []', '"attrs": [1], "parents": []', $s)), 'bundle: attrs as a list');
    Run::eq('loaded', $edit('entities.json', static fn (string $s): string => str_replace('"attrs": {"region": "US"}, "parents": []', '"attrs": [], "parents": {}', $s)), 'bundle: empty attrs [] and parents {} load, as in the reference');
    Run::eq('entities_parse', $edit('entities.json', static fn (string $s): string => substr($s, 0, -2) . ',' . substr($s, 2)), 'bundle: a duplicate entity');
    Run::eq('catalog_parse', $edit('catalog.json', static fn (string $s): string => str_replace('"mask": "redact"', '"mask": "hide"', $s)), 'bundle: an unknown mask');
    Run::eq('catalog_parse', $edit('catalog.json', static fn (string $s): string => str_replace('"entity_type": "Refund"', '"entity_type": "Re fund"', $s)), 'bundle: a malformed entity type');
    Run::eq('catalog_parse', $edit('catalog.json', static fn (string $s): string => '[]'), 'bundle: catalog.json as a list');
    Run::eq('roles_parse', $edit('roles.json', static fn (string $s): string => str_replace('"max_ttl": 600', '"max_tll": 600', $s)), 'bundle: a misspelt role key');
    Run::eq('roles_parse', $edit('roles.json', static fn (string $s): string => str_replace('"max_ttl": 600', '"max_ttl": 600.0', $s)), 'bundle: max_ttl 600.0 is not an integer');
    Run::eq('roles_parse', $edit('roles.json', static fn (string $s): string => str_replace('"budget": {"EUR": 10000}', '"budget": {"EUR": 1e4}', $s)), 'bundle: a role budget written 1e4 is a float');
    Run::eq('roles_parse', $edit('roles.json', static fn (string $s): string => str_replace('"members": [{"type": "Group", "id": "support"}]', '"members": []', $s)), 'bundle: a role without members');
    Run::eq('roles_parse', $edit('roles.json', static fn (string $s): string => str_replace('"bindings": {', '"bindings": [], "x": {', $s)), 'bundle: bindings as a list');
    Run::eq('roles_parse', $edit('roles.json', static fn (string $s): string => '{"roles": []}'), 'bundle: roles as a list');
    Run::eq('loaded', $edit('roles.json', static fn (string $s): string => '{"roles": {}}'), 'bundle: no roles at all loads');
    unlink("$b/policies.json");
    Run::eq('bundle_io', $load(), 'bundle: no policies.json');
    Run::eq('bundle_io', $e->call('reload')['error']['code'] ?? null, 'bundle: reload refuses that too');
    Run::eq($version, $e->call('info')['policy_version'], 'bundle: and still answers from the bundle it has');
    $e->close();
    // CRLF checkouts have the same version
    $crlf = "$work/bundle-crlf";
    Run::copyDir(Run::$bundle, $crlf);
    foreach (['policies.json', 'entities.json', 'catalog.json', 'roles.json', 'policies/crm.cedar', 'policies/billing.cedar', 'policies/delegation.cedar', 'policies/hr.cedar', 'policies/roles.cedar'] as $f) {
        file_put_contents("$crlf/$f", str_replace("\n", "\r\n", (string) file_get_contents("$crlf/$f")));
    }
    $e = new Engine(['bundle_dir' => $crlf]);
    Run::eq($version, $e->call('info')['policy_version'], 'bundle: a checkout with CRLF line endings has the same version and still matches its sources');
    $e->close();

    // ---- Strictness (0.3), spec/PORTING.md: one test per rule ----
    // audit lines end at "\n" and nowhere else
    $sdir = Run::dir('strict-state');
    $e1 = new Engine(Run::confConfig($sdir));
    $e2 = new Engine(Run::confConfig($sdir));
    $odd = "a\u{2028}b\u{2029}c\u{85}d\re\x0b\x0c\x1c";
    Run::eq($odd, $e1->call('revoke', ['token_id' => $odd])['revoked'] ?? null, 'strict: a record with U+2028, U+2029, U+0085 and CR in it is written');
    Run::eq(true, $e2->call('revoke', ['token_id' => 'next'])['ok'], 'strict: a second long-lived engine chains onto that record');
    Run::eq(true, $e1->call('revoke', ['token_id' => 'third'])['ok'], 'strict: and the first one onto the second');
    $tail = $e1->call('audit_tail', ['n' => 3])['records'];
    Run::ok(count($tail) === 3 && $tail[0]['token_id'] === $odd && $tail[2]['seq'] === 3, 'strict: audit_tail returns it whole', Run::show($tail));
    Run::ok($e2->call('audit_verify')['records'] === 3 && substr_count((string) file_get_contents("$sdir/audit.jsonl"), "\n") === 3, 'strict: three records, three lines, one valid chain');
    if ($python) {
        [$code, $out, $err] = Run::py(['audit', 'verify', '--config', Run::writeJson("$sdir/cfg.json", Run::confConfig($sdir))]);
        Run::ok($code === 0 && Json::decode($out)['head'] === $e1->call('audit_verify')['head'], 'strict: the reference verifies that log to the same head', $out . $err);
        [$code, $out] = Run::py(['audit', 'tail', '-n', '3', '--config', "$sdir/cfg.json"]);
        Run::ok($code === 0 && count(explode("\n", trim($out, "\n"))) === 3, 'strict: and its audit tail prints three records', $out);
    }
    // files that are not UTF-8
    $good = (string) file_get_contents("$sdir/audit.jsonl");
    file_put_contents("$sdir/audit.jsonl", $good . "\xff\xfe\n");
    Run::eq('audit_broken', $e1->call('audit_verify')['error']['code'] ?? null, 'strict: an audit log that is not UTF-8 is audit_broken');
    $code = '';
    try {
        new Engine(Run::confConfig($sdir));
    } catch (EngineError $ex) {
        $code = $ex->errorCode;
    } catch (\Throwable $ex) {
        $code = get_class($ex);
    }
    Run::eq('audit_broken', $code, 'strict: and a new engine refuses to start on it with that error, not another exception');
    file_put_contents("$sdir/audit.jsonl", $good);
    file_put_contents("$sdir/state.json", "{\"revoked\":{\"\xff\":1}}");
    Run::eq('state_io', $e1->call('info')['error']['code'] ?? null, 'strict: a state.json that is not UTF-8 is state_io');
    $code = '';
    try {
        new Engine(Run::confConfig($sdir));
    } catch (EngineError $ex) {
        $code = $ex->errorCode;
    } catch (\Throwable $ex) {
        $code = get_class($ex);
    }
    Run::eq('state_io', $code, 'strict: also from the constructor');
    $e1->close();
    $e2->close();
    $sb = "$work/bundle-strict";
    Run::copyDir(Run::$bundle, $sb);
    $loadS = static function () use ($sb): string {
        try {
            (new Engine(['bundle_dir' => $sb]))->close();
            return 'loaded';
        } catch (EngineError $e) {
            return $e->errorCode;
        } catch (\Throwable $e) {
            return get_class($e);
        }
    };
    $editS = static function (string $file, callable $change) use ($sb, $loadS): string {
        $orig = (string) file_get_contents("$sb/$file");
        file_put_contents("$sb/$file", $change($orig));
        $r = $loadS();
        file_put_contents("$sb/$file", $orig);
        return $r;
    };
    foreach (['policies.json', 'entities.json', 'catalog.json', 'roles.json', 'policies/crm.cedar'] as $file) {
        Run::eq('bundle_io', $editS($file, static fn (string $s): string => $s . "\n\xc3\x28\n"), "strict: $file that is not UTF-8 is bundle_io");
    }
    foreach (['{}' => 'an empty object', '{"a": 1}' => 'an object', '[1]' => 'a list of numbers', '[[]]' => 'a list of lists', '"x"' => 'a string', '0' => 'a number', 'null' => 'null'] as $text => $what) {
        Run::eq('entities_parse', $editS('entities.json', static fn (string $s): string => (string) $text), "strict: entities.json that is $what is entities_parse");
    }
    Run::eq('loaded', $editS('entities.json', static fn (string $s): string => '[]'), 'strict: (control) entities.json [] loads');
    // entity type names match in full
    Run::ok(Cedar::validType('User') && Cedar::validType('A::B_1') && !Cedar::validType("User\n") && !Cedar::validType("A::B\n") && !Cedar::validType('') && !Cedar::validType('A::')
        && !Cedar::validType('1A') && !Cedar::validType(' A') && !Cedar::validType("A\r") && !Cedar::validType(5), 'strict: a type name with a trailing newline is not a type name');
    Run::eq('catalog_parse', $editS('catalog.json', static fn (string $s): string => str_replace('"entity_type": "Refund"', '"entity_type": "Refund\n"', $s)), 'strict: nor in the catalog');
    Run::eq('entities_parse', $editS('entities.json', static fn (string $s): string => str_replace('"type": "AgentGroup", "id": "support-agents"}, "attrs"', '"type": "AgentGroup\n", "id": "support-agents"}, "attrs"', $s)), 'strict: nor in entities.json');
    Run::eq('roles_parse', $editS('roles.json', static fn (string $s): string => str_replace('{"type": "User", "id": "carol"}', '{"type": "User\n", "id": "carol"}', $s)), 'strict: nor in a role member');
    // policy JSON shapes are checked at load
    $policy = static function (string $json): string {
        try {
            new Policy('p', Json::decode($json));
            return 'loaded';
        } catch (\SmartDelegate\Unsupported) {
            return 'refused';
        } catch (\Throwable $e) {
            return get_class($e);
        }
    };
    $pol = static fn (string $more): string => '{"effect":"permit","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"}' . $more . '}';
    $when = static fn (string $body): string => $pol(',"conditions":[{"kind":"when","body":' . $body . '}]');
    $ctx = '{"Var":"context"}';
    Run::eq('loaded', $policy($pol('')), 'strict: (control) a minimal policy loads');
    Run::eq('loaded', $policy($when('{"Set":[]}') ), 'strict: (control) an empty Set literal loads');
    Run::eq('loaded', $policy($pol(',"annotations":null,"conditions":[]')), 'strict: (control) annotations null is no annotations');
    foreach ([
        'conditions as an empty object' => $pol(',"conditions":{}'),
        'conditions as an empty string' => $pol(',"conditions":""'),
        'conditions as null' => $pol(',"conditions":null'),
        'conditions as an object' => $pol(',"conditions":{"kind":"when","body":{"Value":true}}'),
        'a condition that is not an object' => $pol(',"conditions":["when"]'),
        'annotations as a list' => $pol(',"annotations":["id"]'),
        'annotations as a string' => $pol(',"annotations":"id"'),
        'a Set literal as an empty object' => $when('{"Set":{}}'),
        'a Set literal as a string' => $when('{"Set":"ab"}'),
        'a Record literal as a list' => $when('{"Record":[]}'),
        'a Record literal as a non-empty list' => $when('{"Record":[{"Value":1}]}'),
        'a like pattern as a string' => $when('{"like":{"left":' . $ctx . ',"pattern":""}}'),
        'a like pattern as an object' => $when('{"like":{"left":' . $ctx . ',"pattern":{}}}'),
        'a like pattern with a bare character' => $when('{"like":{"left":' . $ctx . ',"pattern":["a"]}}'),
        'scope entities as an object' => '{"effect":"permit","principal":{"op":"All"},"action":{"op":"in","entities":{}},"resource":{"op":"All"}}',
        'scope entities as a string' => '{"effect":"permit","principal":{"op":"All"},"action":{"op":"in","entities":""},"resource":{"op":"All"}}',
        'a scope type with a trailing newline' => '{"effect":"permit","principal":{"op":"is","entity_type":"User\n"},"action":{"op":"All"},"resource":{"op":"All"}}',
        'an `is` type with a trailing newline' => $when('{"is":{"left":{"Var":"principal"},"entity_type":"User\n"}}'),
        'a policy that is a list' => '[]',
    ] as $what => $json) {
        Run::eq('refused', $policy($json), "strict: $what is refused when the policy loads");
    }
    Run::eq('policy_parse', $editS('policies.json', static fn (string $s): string => preg_replace('/"conditions":\s*\[\s*\]/', '"conditions": {}', $s, 1, $cnt)), 'strict: and through the bundle that is policy_parse');
    Run::eq('policy_parse', $editS('policies.json', static fn (string $s): string => preg_replace('/"annotations":\s*\{/', '"annotations": ["x"], "x": {', $s, 1)), 'strict: and so is annotations as a list');
    // containsAll / containsAny check both operands before looking at contents
    $sets = static function (string $op, string $left, string $right) use ($when): string {
        $p = new Policy('p', Json::decode($when('{"' . $op . '":{"left":' . $left . ',"right":' . $right . '}}')));
        $r = Cedar::isAuthorized(['p' => $p], new Env(new Entity('U', 'u'), new Entity('Action', 'a'), new Entity('R', 'r'), [], new Store()));
        return $r['errors'] ? 'error' : $r['decision'];
    };
    foreach (['containsAll', 'containsAny'] as $op) {
        Run::eq('error', $sets($op, '{"Value":1}', '{"Set":[]}'), "strict: $op: a receiver that is not a set is an error even when the argument is empty");
        Run::eq('error', $sets($op, '{"Set":[]}', '{"Value":"x"}'), "strict: $op: an argument that is not a set is an error even when the receiver is empty");
        Run::eq('error', $sets($op, '{"Value":1}', '{"Value":2}'), "strict: $op: neither is a set");
    }
    Run::eq('allow', $sets('containsAll', '{"Set":[{"Value":1}]}', '{"Set":[]}'), 'strict: (control) containsAll of the empty set is true');
    Run::eq('deny', $sets('containsAny', '{"Set":[{"Value":1}]}', '{"Set":[]}'), 'strict: (control) containsAny of the empty set is false');
    // base64url is strict
    foreach (['', '=', 'QQ==', 'QQ=', "QQ\n", ' QQ', 'Q Q', 'Q!Q', 'QQ+', 'QQ/', 'Q.Q', 'Q', 'QQQQQ', "QQ\0", 'QQ%3D', "Q\u{e9}"] as $bad) {
        $threw = false;
        try {
            Tokens::b64uDec($bad);
        } catch (\UnexpectedValueException) {
            $threw = true;
        }
        Run::ok($threw, 'strict: not base64url: ' . addcslashes($bad, "\0..\37\177..\377"));
    }
    Run::ok(Tokens::b64uDec('QQ') === 'A' && Tokens::b64uDec('-_-_') === "\xfb\xff\xbf" && Tokens::b64uDec('QUI') === 'AB' && Tokens::b64uDec('QUJD') === 'ABC', 'strict: (control) base64url decodes');
    $e = new Engine(['bundle_dir' => Run::$bundle, 'allow_test_clock' => true]);
    $tk = $e->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'cap' => ['actions' => ['read']], 'now' => T0])['token'];
    [$h, $b, $sg] = explode('.', $tk);
    Run::eq(true, $e->call('inspect_token', ['token' => $tk, 'now' => T0])['valid'] ?? null, 'strict: (control) the token is valid');
    $spellings = 0;
    foreach ([0, 1, 2] as $part) {
        foreach (['!', '=', ' ', "\n", '+', '/', '.', '%', "\t"] as $junk) {
            foreach ([0, 5, -1] as $at) {
                $parts = [$h, $b, $sg];
                $parts[$part] = $at === -1 ? $parts[$part] . $junk : substr($parts[$part], 0, $at) . $junk . substr($parts[$part], $at);
                $r = $e->call('inspect_token', ['token' => implode('.', $parts), 'now' => T0]);
                $spellings += ($r['valid'] ?? null) === false && $r['reason'] === 'token_invalid' ? 0 : 1;
            }
        }
    }
    Run::eq(0, $spellings, 'strict: 81 respellings of a valid token (a character outside the alphabet anywhere in any of the three parts) are all token_invalid');
    $std = strtr($sg, '-_', '+/');
    Run::ok($std === $sg || ($e->call('inspect_token', ['token' => "$h.$b.$std", 'now' => T0])['valid'] ?? null) === false, 'strict: the same signature in the standard alphabet (+ /) is refused');
    Run::eq('token_invalid', $e->call('authorize', ['token' => "$h.$b.$sg=", 'action' => 'read', 'resource' => ['path' => 'crm.customer'], 'now' => T0])['reason'] ?? null, 'strict: and authorize refuses a padded token');
    // token claims: anc is an array of strings
    $kid2 = $e->call('info')['key_id'];
    $e->close();
    $e = new Engine(['bundle_dir' => Run::$bundle, 'signing_key' => $pk8, 'allow_test_clock' => true]);
    foreach (['"abc"' => 'a string', '""' => 'an empty string', '{}' => 'an object', '{"a":"b"}' => 'an object with a string', 'null' => 'null', '[["a"]]' => 'a list of lists', '0' => 'a number'] as $anc => $what) {
        $claimsJson = '{"iss":"smartdelegate://local","aud":"smartdelegate","sub":"user:alice","iat":' . T0 . ',"exp":' . (T0 + 60) . ',"jti":"j","act":{"sub":"agent:support-bot"},"cap":{"actions":["read"]},"anc":' . $anc . '}';
        Run::eq('token rejected: malformed claims', (string) ($e->call('inspect_token', ['token' => $resign($hd, $claimsJson), 'now' => T0])['detail'] ?? 'valid'), "strict: `anc` that is $what is refused");
    }
    Run::eq('valid', (string) ($e->call('inspect_token', ['token' => $resign($hd, str_replace('"anc":0', '"anc":["a","b"]', $claimsJson)), 'now' => T0])['detail'] ?? 'valid'), 'strict: (control) `anc` as a list of strings is accepted');
    // F-1: a malformed `lim` is not a token
    $withLim = static fn (string $lim): string => (string) ($e->call('inspect_token', ['token' => $resign($hd, str_replace('"anc":0', '"anc":["p"],"lim":' . $lim, $claimsJson)), 'now' => T0])['detail'] ?? 'valid');
    foreach (['"x"' => 'a string', '[]' => 'an empty list', '[{"EUR":1}]' => 'a list', 'null' => 'null', '5' => 'a number', '{"p":5}' => 'an object of numbers', '{"p":[]}' => 'an object of lists',
        '{"p":{"EUR":-1}}' => 'a negative amount', '{"p":{"EUR":"9"}}' => 'an amount as a string', '{"p":{"EUR":1.0}}' => 'an amount as a float', '{"p":{"EUR":true}}' => 'an amount as a bool',
        '{"p":{"EUR":null}}' => 'a null amount', '{"p":{"EUR":1},"q":"x"}' => 'one good entry and one bad'] as $lim => $what) {
        Run::eq('token rejected: malformed claims', $withLim((string) $lim), "F-1: `lim` that is $what is refused");
    }
    foreach (['{}', '{"p":{}}', '{"p":{"EUR":0,"840":99999999999999999999}}'] as $lim) {
        Run::eq('valid', $withLim($lim), "F-1: (control) `lim` $lim is accepted");
    }
    $limTok = $resign($hd, str_replace(['"anc":0', '"actions":["read"]'], ['"anc":["p"],"lim":{"p":{"EUR":100}}', '"actions":["create"],"resources":["billing.refund/*"],"budget":{"EUR":500}'], $claimsJson));
    $sp = static fn (int $amount): string => (string) ($e->call('authorize', ['token' => $limTok, 'action' => 'create', 'resource' => ['path' => 'billing.refund', 'id' => 'r'], 'now' => T0,
        'context' => ['spend' => ['currency' => 'EUR', 'amount' => $amount]]])['reason'] ?? '?');
    Run::eq(['budget_exceeded', 'policy_permit', 'budget_exceeded'], [$sp(101), $sp(100), $sp(1)], 'F-1: the ancestor limit in `lim` (100) is enforced although the token\'s own budget (500) would allow more');
    // F-2: the cut-off of a revoked user never moves back
    $r1 = $e->call('revoke', ['user' => 'u', 'now' => T0 + 100]);
    $r2 = $e->call('revoke', ['user' => 'u', 'now' => T0 - 100]);
    $r3 = $e->call('revoke', ['user' => 'u', 'now' => T0 + 200]);
    Run::eq([T0 + 100, T0 + 100, T0 + 200], [$r1['issued_up_to'] ?? null, $r2['issued_up_to'] ?? null, $r3['issued_up_to'] ?? null], 'F-2: revoking a user again with an earlier clock keeps the later cut-off');
    $e->close();
    // creating the signing key when several processes start on an empty state directory at once
    $ids = [];
    $failures = '';
    for ($round = 0; $round < 5; $round++) {
        $race = Run::dir('race');
        $procs = [];
        for ($i = 0; $i < 8; $i++) {
            $procs[] = proc_open([PHP_BINARY, Run::$bin, 'info', '--bundle', Run::$bundle, '--state', "$race/state"], [1 => ['file', "$race/out$i", 'w'], 2 => ['file', "$race/err$i", 'w']], $pp);
        }
        $roundIds = [];
        foreach ($procs as $i => $p) {
            $code = proc_close($p);
            $out = (string) file_get_contents("$race/out$i");
            if ($code !== 0) {
                $failures .= " [exit $code: " . trim((string) file_get_contents("$race/err$i")) . ']';
            } else {
                $roundIds[] = Json::decode($out)['key_id'];
            }
        }
        $ids[] = count(array_unique($roundIds)) . '/' . count($roundIds);
    }
    // a key file that exists but is still empty (another port creates it, then writes it) is waited for;
    // it must never be read as "no signing key"
    $late = Run::dir('late-key');
    mkdir("$late/state");
    touch("$late/state/signing_key.pk8.b64");
    [$lateKey, $latePub] = Bundle::keygen();
    $writer = proc_open([PHP_BINARY, '-r', 'usleep(400000); file_put_contents($argv[1], $argv[2]);', "$late/state/signing_key.pk8.b64", $lateKey], [], $pp);
    Run::$procs[] = $writer;
    $le = new Engine(['bundle_dir' => Run::$bundle, 'state_dir' => "$late/state"]);
    $li = $le->call('info');
    proc_close($writer);
    Run::ok($li['can_issue'] === true && $li['public_key'] === $latePub, 'strict: an engine that finds the key file still empty waits for the key instead of starting without one', Run::show($li));
    $le->close();
    Run::ok($failures === '' && $ids === array_fill(0, 5, '1/8'), 'strict: 8 processes starting at once on an empty state directory all end up with one signing key (5 rounds)', implode(' ', $ids) . $failures);

    // the command line: exit codes and configuration
    $cfgDir = Run::dir('cli');
    Run::copyDir(Run::$bundle, "$cfgDir/b");
    file_put_contents("$cfgDir/smartdelegate.json", '{"bundle_dir": "b", "state_dir": "s", "allow_test_clock": true}');
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'info', '--config', "$cfgDir/smartdelegate.json"]);
    Run::ok($code === 0 && is_dir("$cfgDir/s") && str_contains($out, "\n  \"implementation\": \"php\",\n"), 'cli: relative paths in the config file are relative to the file; output is indented JSON', $out);
    $cwd = getcwd();
    chdir($cfgDir);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'info']);
    Run::ok($code === 0 && Json::decode($out)['version'] === '0.3.0', 'cli: ./smartdelegate.json is found without --config', $out);
    [$code, $tok] = Run::exec([PHP_BINARY, Run::$bin, 'token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '{"actions":["read"],"resources":["crm.customer/*"]}', '--raw']);
    $tok = trim($tok);
    Run::ok($code === 0 && substr_count($tok, '.') === 2, 'cli: token issue --raw prints the token');
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'authorize', '--token', $tok, '--action', 'read', '--resource', 'crm.customer/c-1']);
    Run::ok($code === 0 && Json::decode($out)['effect'] === 'allow', 'cli: an allow exits 0', $out);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'authorize', '--token', $tok, '--action', 'delete', '--resource', 'crm.customer/c-1']);
    Run::ok($code === 2 && Json::decode($out)['reason'] === 'capability_action', 'cli: a deny exits 2', $out);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'authorize', '--token', $tok, '--action', 'read', '--resource', 'crm.customer/c-1', '--context', '[]']);
    Run::ok($code === 1 && Json::decode($out)['error']['code'] === 'invalid_context', 'cli: an error exits 1; --context [] is a list, not an object', $out);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'authorize', '--token', $tok, '--action', 'update', '--resource', 'crm.customer/c-1', '--data', '{"tier": 1}', '--strict', '--dry-run']);
    Run::ok($code === 2 && Json::decode($out)['reason'] === 'capability_action', 'cli: --data makes it a filter; --strict and --dry-run are switches', $out);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'explain', '--token', $tok, '--action', 'read', '--resource', 'crm.customer']);
    Run::ok($code === 0 && is_array(Json::decode($out)['explain']), 'cli: explain', $out);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'call', 'inspect_token', '--input', '-'], '{"token": "' . $tok . '"}');
    Run::ok($code === 0 && Json::decode($out)['valid'] === true, 'cli: call <op> --input - reads standard input', $out);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'token', 'revoke', '--token', $tok]);
    Run::ok($code === 0, 'cli: token revoke', $out);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'token', 'inspect', '--token', $tok]);
    Run::ok($code === 0 && Json::decode($out)['reason'] === 'token_revoked', 'cli: token inspect', $out);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'audit', 'tail', '-n', '2']);
    Run::ok($code === 0 && count(explode("\n", trim($out))) === 2 && Json::decode(explode("\n", $out)[1])['event'] === 'token_revoked', 'cli: audit tail -n 2 prints two compact records', $out);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'approvals', '--shadow']);
    Run::ok($code === 0 && str_contains($out, '"pending": {}'), 'cli: approvals', $out);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'policy', 'test']);
    Run::ok($code === 0 && preg_match('/^(\d+) tests, 0 failed$/m', $out, $m) === 1 && (int) $m[1] > 0, 'cli: policy test runs the bundle\'s own tests', $out);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'info'], null, ['SMARTDELEGATE_CONFIG' => "$cfgDir/nope.json"]);
    Run::eq(1, $code, 'cli: SMARTDELEGATE_CONFIG is honoured (a missing file is an error)');
    chdir($cwd);
    [$code, , $err] = Run::exec([PHP_BINARY, Run::$bin, 'info'], null, ['SMARTDELEGATE_CONFIG' => '']);
    Run::ok($code === 1 && str_contains($err, 'no bundle'), 'cli: without a configuration there is nothing to load', $err);
    [$code, $out] = Run::exec([PHP_BINARY, Run::$bin, 'info', '--bundle', Run::$bundle, '--state', "$cfgDir/s2", '--shadow']);
    Run::ok($code === 0 && Json::decode($out)['mode'] === 'shadow' && is_dir("$cfgDir/s2"), 'cli: --bundle, --state and --shadow', $out);
    [$code, $out] = Run::exec([Run::$port . '/run_conformance.sh']);
    Run::ok($code === 0 && preg_match('/^eval: (\d+) cases, 0 failed$/m', $out, $m) === 1 && (int) $m[1] >= 95 && preg_match('/^conformance: (\d+) cases, 0 failed$/m', $out, $m2) === 1 && (int) $m2[1] >= 73, 'cli: run_conformance.sh', substr($out, -300));
    Run::end('7. keys, tokens, ID tokens, failing closed, command line');
}

// ---- main ----------------------------------------------------------------------------

Run::$port = dirname(__DIR__);
Run::$root = dirname(__DIR__, 3);
Run::$bin = Run::$port . '/bin/smartdelegate-php';
Run::$bundle = Run::$root . '/spec/conformance/bundle';
Run::$vectors = Run::$root . '/spec/conformance/vectors';
Run::$tmp = Conformance::tempDir('smartdelegate-php-test-');
register_shutdown_function([Run::class, 'cleanup']);
if (function_exists('pcntl_signal')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGINT, static function (): void {
        exit(130);
    });
}
putenv('SMARTDELEGATE_CONFIG');
putenv('SMARTDELEGATE_ADMIN_KEY');
putenv('SMARTDELEGATE_PEP_KEY');

$only = null;
foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--verbose' || $arg === '-v') {
        Run::$verbose = true;
    } elseif (str_starts_with($arg, '--only=')) {
        $only = explode(',', substr($arg, 7));
    } else {
        fwrite(STDERR, "usage: php test/run.php [--only=1,2,3,4,5,6,7] [--verbose]\n");
        exit(1);
    }
}
$sections = ['1' => 'section_eval', '2' => 'section_vectors', '3' => 'section_rest', '4' => 'section_interop', '5' => 'section_json', '6' => 'section_front_controller', '7' => 'section_keys'];
foreach ($sections as $id => $fn) {
    if ($only !== null && !in_array((string) $id, $only, true)) {
        continue;
    }
    try {
        $fn();
    } catch (\Throwable $e) {
        Run::$failed++;
        Run::note("$id. ABORTED: " . get_class($e) . ': ' . $e->getMessage() . ' at ' . basename($e->getFile()) . ':' . $e->getLine());
        Run::logFailure("section $id ABORTED: " . get_class($e) . ': ' . $e->getMessage() . ' at ' . basename($e->getFile()) . ':' . $e->getLine());
    }
}
echo "\n", str_repeat('-', 72), "\n", implode("\n", Run::$summary), "\n";
echo Run::$failed === 0 ? 'OK: ' . Run::$checks . " checks, 0 failed\n" : 'FAILED: ' . Run::$failed . ' of ' . Run::$checks . " checks failed\n";
exit(Run::$failed === 0 ? 0 : 1);
