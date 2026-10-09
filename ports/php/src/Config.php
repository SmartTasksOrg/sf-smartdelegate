<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * The configuration file of the command line, the daemon and the front
 * controller: the engine configuration of spec/API.md plus `listen`,
 * `admin_key` and `pep_key`. Resolved exactly as the reference CLI does.
 */
final class Config
{
    /**
     * Config file + overrides. Relative `bundle_dir`, `state_dir` and
     * `idp.jwks_file` in the file are relative to the file.
     *
     * The file is `$file`, else the environment variable SMARTDELEGATE_CONFIG,
     * else ./smartdelegate.json when it exists, else none.
     *
     * @throws \RuntimeException with a message for the user
     */
    public static function load(?string $file = null, ?string $bundle = null, ?string $state = null, bool $shadow = false): JsonObject
    {
        $env = getenv('SMARTDELEGATE_CONFIG');
        $path = ($file !== null && $file !== '') ? $file
            : (($env !== false && $env !== '') ? $env : (file_exists('smartdelegate.json') ? 'smartdelegate.json' : null));
        $cfg = new JsonObject();
        if ($path !== null) {
            $text = is_dir($path) ? false : @file_get_contents($path);
            if ($text === false) {
                throw new \RuntimeException("$path: cannot read the configuration file");
            }
            try {
                $cfg = Json::decodeBytes($text);
            } catch (JsonError $e) {
                throw new \RuntimeException("$path: " . $e->getMessage());
            }
            if (!$cfg instanceof JsonObject) {
                throw new \RuntimeException("$path: the configuration must be a JSON object");
            }
            $base = dirname(realpath($path) ?: $path);
            $fix = static fn (string $p): string => str_starts_with($p, '/') || preg_match('/^[A-Za-z]:[\\\\\/]/', $p) === 1 ? $p : $base . '/' . $p;
            foreach (['bundle_dir', 'state_dir'] as $k) {
                if (is_string($cfg->get($k))) {
                    $cfg->set($k, $fix($cfg->get($k)));
                }
            }
            $idp = $cfg->get('idp');
            if ($idp instanceof JsonObject && is_string($idp->get('jwks_file'))) {
                $idp->set('jwks_file', $fix($idp->get('jwks_file')));
            }
        }
        if ($bundle !== null && $bundle !== '') {
            $cfg->set('bundle_dir', $bundle);
        }
        if ($state !== null && $state !== '') {
            $cfg->set('state_dir', $state);
        }
        if ($shadow) {
            $cfg->set('mode', 'shadow');
        }
        foreach (['admin_key' => 'SMARTDELEGATE_ADMIN_KEY', 'pep_key' => 'SMARTDELEGATE_PEP_KEY'] as $k => $name) {
            $v = getenv($name);
            if ($v !== false && $v !== '') {
                $cfg->set($k, $v);
            }
        }
        if (!Json::truthy($cfg->get('bundle_dir'))) {
            throw new \RuntimeException('no bundle: pass --config FILE or --bundle DIR (or set SMARTDELEGATE_CONFIG)');
        }
        return $cfg;
    }

    /** The key under `name` as a string, or "" when it is missing or not a string. */
    public static function key(JsonObject $cfg, string $name): string
    {
        $v = $cfg->get($name);
        return is_string($v) ? $v : '';
    }
}
