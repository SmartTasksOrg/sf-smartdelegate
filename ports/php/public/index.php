<?php
/**
 * Front controller: the REST routes of `smartdelegate serve` for php-fpm,
 * Apache (mod_php) or `php -S host:port public/index.php`.
 *
 * Configuration: the environment variable SMARTDELEGATE_CONFIG names the same
 * JSON file the command line uses (engine settings plus `admin_key` and
 * `pep_key`; SMARTDELEGATE_ADMIN_KEY / SMARTDELEGATE_PEP_KEY override them).
 *
 * Every request builds a fresh engine. Read the README section "Under
 * php-fpm" before relying on this: state kept in the state directory works
 * across requests, state kept in memory (rate limits) does not.
 */
declare(strict_types=1);

// the response body is JSON; PHP's own diagnostics belong in the server log, never in the response
ini_set('display_errors', '0');
require dirname(__DIR__) . '/src/autoload.php';

use SmartDelegate\Config;
use SmartDelegate\Engine;
use SmartDelegate\EngineError;
use SmartDelegate\JsonObject;
use SmartDelegate\Server;

(static function (): void {
    $send = static function (int $status, JsonObject $body): void {
        $raw = Server::encode($body);
        http_response_code($status);
        header('Content-Type: application/json');
        header('Content-Length: ' . strlen($raw));
        echo $raw;
    };
    $fail = static function (int $status, string $code, string $message) use ($send): void {
        $send($status, new JsonObject(['ok' => false, 'error' => new JsonObject(['code' => $code, 'message' => $message])]));
    };

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($method !== 'GET' && $method !== 'POST') {
        $fail(501, 'unsupported_method', "Unsupported method ('$method')");
        return;
    }
    $target = $_SERVER['REQUEST_URI'] ?? '/';
    $script = $_SERVER['SCRIPT_NAME'] ?? '';
    if ($script !== '' && $script !== '/' && str_starts_with($target, $script . '/')) {
        $target = substr($target, strlen($script));   // /index.php/v1/info
    }

    try {
        $cfg = Config::load();
        $admin = Config::key($cfg, 'admin_key');
        $pep = Config::key($cfg, 'pep_key');
        $problem = Server::keyProblem($admin, $pep);
        if ($problem !== null) {
            throw new \RuntimeException($problem);
        }
        $engine = new Engine($cfg);
    } catch (EngineError | \RuntimeException $e) {
        // the details (paths, key problems) are for the operator, not for the caller
        error_log('smartdelegate: ' . $e->getMessage());
        $fail(500, $e instanceof EngineError ? $e->errorCode : 'invalid_config', 'the decision service is not configured; see the server log');
        return;
    }

    $raw = '';
    $bodyError = null;
    $path = explode('?', $target, 2)[0];
    if ($method === 'POST' && $path !== '/healthz') {
        $cl = $_SERVER['CONTENT_LENGTH'] ?? ($_SERVER['HTTP_CONTENT_LENGTH'] ?? '');
        if ($cl !== '' && preg_match('/^\s*[-+]?[0-9]+\s*$/', (string) $cl) !== 1) {
            $bodyError = 'bad Content-Length';
        } elseif ($cl !== '') {
            $len = (float) $cl;
            if ($len > Server::MAX_BODY) {
                $bodyError = 'request body is too large';
            } elseif ($len > 0) {
                $raw = (string) file_get_contents('php://input', false, null, 0, (int) $len);
            }
        }
    }
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null);
    if ($auth === null && function_exists('getallheaders')) {
        foreach (getallheaders() ?: [] as $name => $value) {
            if (strcasecmp((string) $name, 'Authorization') === 0) {
                $auth = (string) $value;
                break;
            }
        }
    }
    try {
        [$status, $body] = Server::handle($engine, $admin, $pep, $method, $target, $auth, $raw, $bodyError);
    } catch (\Throwable $e) {
        [$status, $body] = [400, (new EngineError('internal', get_class($e) . ': ' . $e->getMessage()))->toJson()];
    } finally {
        $engine->close();
    }
    $send($status, $body);
})();
