<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * Runner for the shared conformance suites: the policy-evaluation cases, the
 * engine vectors, and a bundle's own tests.
 *
 * A vector case is a list of steps; each step names an operation, its input
 * and a partial expected result. `save` stores a value from a result and
 * `"$name"` in a later input is replaced by it.
 */
final class Conformance
{
    public static function substitute(mixed $v, array $variables): mixed
    {
        if (is_string($v) && str_starts_with($v, '$')) {
            $name = substr($v, 1);
            return array_key_exists($name, $variables) ? $variables[$name] : $v;
        }
        if (is_array($v)) {
            foreach ($v as $k => $x) {
                $v[$k] = self::substitute($x, $variables);
            }
            return $v;
        }
        if ($v instanceof JsonObject) {
            $out = [];
            foreach ($v->m as $k => $x) {
                $out[$k] = self::substitute($x, $variables);
            }
            return new JsonObject($out);
        }
        return $v;
    }

    /**
     * Every key in `expect` must be present and equal in `actual`; objects
     * recursively, everything else exactly. An expected null also matches a
     * missing key. Returns a mismatch or null.
     */
    public static function subset(mixed $expect, mixed $actual, string $path = ''): ?string
    {
        if ($expect instanceof JsonObject && $actual instanceof JsonObject) {
            foreach ($expect->m as $k => $ev) {
                $p = $path !== '' ? "$path.$k" : (string) $k;
                if (!array_key_exists($k, $actual->m)) {
                    if ($ev === null) {
                        continue;
                    }
                    return "$p: missing, expected " . Json::encode($ev);
                }
                $m = self::subset($ev, $actual->m[$k], $p);
                if ($m !== null) {
                    return $m;
                }
            }
            return null;
        }
        if (is_bool($expect) !== is_bool($actual) || !Json::pyEq($expect, $actual)) {
            return "$path: expected " . Json::encode($expect) . ', got ' . Json::encode($actual);
        }
        return null;
    }

    /**
     * @param callable(string,mixed):array $call an engine's or a client's call()
     * @return array{name:mixed,passed:bool,failures:list<array{step:int,op:mixed,mismatch:string}>,steps:int}
     */
    public static function runCase(callable $call, JsonObject $case): array
    {
        $variables = [];
        $failures = [];
        $steps = $case->get('steps');
        foreach (is_array($steps) ? $steps : [] as $n => $step) {
            $op = $step->get('op', '');
            $result = new JsonObject($call(is_string($op) ? $op : '', self::substitute($step->get('input'), $variables)));
            $save = $step->get('save');
            foreach ($save instanceof JsonObject ? $save->m : [] as $name => $key) {
                $cur = $result;
                foreach (explode('.', is_string($key) ? $key : Json::compact($key)) as $part) {
                    $cur = $cur instanceof JsonObject ? $cur->get($part) : null;
                }
                $variables[$name] = $cur;
            }
            $expect = $step->get('expect');
            $m = self::subset(Json::truthy($expect) ? $expect : new JsonObject(), $result);
            if ($m !== null) {
                $failures[] = ['step' => $n, 'op' => $step->get('op'), 'mismatch' => $m];
            }
        }
        return ['name' => $case->get('name'), 'passed' => !$failures, 'failures' => $failures, 'steps' => is_array($steps) ? count($steps) : 0];
    }

    /** @return list<string> sorted *.json files of a directory */
    public static function jsonFiles(string $dir): array
    {
        $out = [];
        foreach (@scandir($dir) ?: [] as $name) {
            if (str_ends_with($name, '.json') && is_file("$dir/$name")) {
                $out[] = "$dir/$name";
            }
        }
        sort($out, SORT_STRING);
        return $out;
    }

    public static function readJson(string $file): mixed
    {
        $text = @file_get_contents($file);
        if ($text === false) {
            throw new EngineError('conformance_io', "$file: cannot read");
        }
        try {
            return Json::decodeBytes($text);
        } catch (JsonError $e) {
            throw new EngineError('conformance_io', "$file: " . $e->getMessage());
        }
    }

    public static function tempDir(string $prefix): string
    {
        for ($i = 0; $i < 100; $i++) {
            $dir = sys_get_temp_dir() . '/' . $prefix . bin2hex(random_bytes(6));
            if (@mkdir($dir, 0700)) {
                return $dir;
            }
        }
        throw new EngineError('conformance_io', 'cannot create a temporary directory');
    }

    public static function removeDir(string $dir): void
    {
        if (!is_dir($dir) || is_link($dir)) {
            @unlink($dir);
            return;
        }
        foreach (scandir($dir) ?: [] as $name) {
            if ($name !== '.' && $name !== '..') {
                self::removeDir("$dir/$name");
            }
        }
        @rmdir($dir);
    }

    /** The configuration every port uses for the vectors, plus the suite's own `config`. */
    public static function config(string $bundleDir, string $stateDir, mixed $suiteConfig, int $maxDepth = 3): JsonObject
    {
        $cfg = new JsonObject(['bundle_dir' => $bundleDir, 'state_dir' => $stateDir, 'allow_test_clock' => true, 'max_depth' => $maxDepth]);
        foreach ($suiteConfig instanceof JsonObject ? $suiteConfig->m : [] as $k => $v) {
            $cfg->m[$k] = $v;   // a suite may add settings, e.g. an identity provider
        }
        return $cfg;
    }

    /**
     * Every case against a fresh engine with its own state directory.
     *
     * @return array{total:int,failed:int,steps:int,results:list<array>,suites:array<string,array{total:int,failed:int}>}
     */
    public static function runVectors(string $vectorsDir, string $bundleDir, int $maxDepth = 3): array
    {
        $results = [];
        $suites = [];
        foreach (self::jsonFiles($vectorsDir) as $file) {
            $doc = self::readJson($file);
            $suite = basename($file, '.json');
            $suites[$suite] = ['total' => 0, 'failed' => 0];
            $cases = $doc instanceof JsonObject ? $doc->get('cases') : null;
            foreach (is_array($cases) ? $cases : [] as $case) {
                $state = self::tempDir('smartdelegate-conf-');
                try {
                    $engine = new Engine(self::config($bundleDir, $state, $doc->get('config'), $maxDepth));
                    try {
                        $r = self::runCase([$engine, 'call'], $case);
                    } finally {
                        $engine->close();
                    }
                } finally {
                    self::removeDir($state);
                }
                $r['suite'] = $suite;
                $results[] = $r;
                $suites[$suite]['total']++;
                $suites[$suite]['failed'] += $r['passed'] ? 0 : 1;
            }
        }
        return ['total' => count($results), 'failed' => count(array_filter($results, static fn (array $r): bool => !$r['passed'])),
            'results' => $results, 'suites' => $suites, 'steps' => array_sum(array_column($results, 'steps'))];
    }

    /**
     * `<bundle>/tests/*.json` against a throwaway engine per case: no state
     * directory, no audit log, test clock on, caller-supplied chains trusted.
     */
    public static function runBundleTests(string $bundleDir): array
    {
        $results = [];
        foreach (self::jsonFiles("$bundleDir/tests") as $file) {
            $doc = self::readJson($file);
            $cases = $doc instanceof JsonObject ? $doc->get('cases') : null;
            foreach (is_array($cases) ? $cases : [] as $case) {
                $engine = new Engine(['bundle_dir' => $bundleDir, 'allow_test_clock' => true, 'trust_caller_chain' => true, 'audit' => false]);
                try {
                    $results[] = self::runCase([$engine, 'call'], $case);
                } finally {
                    $engine->close();
                }
            }
        }
        return ['total' => count($results), 'failed' => count(array_filter($results, static fn (array $r): bool => !$r['passed'])), 'results' => $results];
    }

    /**
     * The policy-evaluation cases (spec/conformance/eval/cases.json): the
     * evaluator must give the real Cedar engine's answer on each, and refuse
     * to load the ones marked `load_error`.
     */
    public static function runEval(string $casesFile): array
    {
        $doc = self::readJson($casesFile);
        $store = new Store($doc->get('entities'));
        $results = [];
        foreach ($doc->get('cases') as $c) {
            $failures = [];
            $expect = $c->get('expect');
            try {
                $policies = [];
                $loadError = null;
                try {
                    foreach ($c->get('policies')->m as $pid => $est) {
                        $policies[$pid] = new Policy((string) $pid, $est);
                    }
                } catch (Unsupported $e) {
                    $loadError = $e->getMessage();
                }
                if (Json::truthy($expect->get('load_error'))) {
                    if ($loadError === null) {
                        $failures[] = ['step' => 0, 'op' => 'load', 'mismatch' => 'the policies loaded; they must be refused'];
                    }
                } elseif ($loadError !== null) {
                    $failures[] = ['step' => 0, 'op' => 'load', 'mismatch' => "the policies were refused: $loadError"];
                } else {
                    $r = $c->get('request');
                    $env = new Env(new Entity($r['principal'][0], $r['principal'][1]), new Entity('Action', $r['action']),
                        new Entity($r['resource'][0], $r['resource'][1]), Cedar::fromJson($r['context']), $store);
                    $got = Cedar::isAuthorized($policies, $env);
                    $errors = array_map(static fn (array $e): string => $e[0], $got['errors']);
                    sort($errors, SORT_STRING);
                    $actual = new JsonObject(['decision' => $got['decision'], 'reasons' => $got['reasons'], 'errors' => $errors]);
                    if (!Json::pyEq($actual, $expect)) {
                        $failures[] = ['step' => 0, 'op' => 'is_authorized', 'mismatch' => 'expected ' . Json::encode($expect) . ', got ' . Json::encode($actual)];
                    }
                }
            } catch (\Throwable $e) {
                $failures[] = ['step' => 0, 'op' => 'evaluate', 'mismatch' => get_class($e) . ': ' . $e->getMessage()];
            }
            $results[] = ['name' => $c->get('name'), 'passed' => !$failures, 'failures' => $failures];
        }
        return ['total' => count($results), 'failed' => count(array_filter($results, static fn (array $r): bool => !$r['passed'])), 'results' => $results];
    }
}
