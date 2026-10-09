<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * REST decision daemon. See spec/openapi.yaml; the routes, key rules, status
 * codes and body limit are those of the reference daemon
 * (src/sf_smartdelegate/daemon.py).
 *
 * Two keys guard it:
 *   pep key    enforcement points: /v1/authorize, /v1/filter, /v1/explain,
 *              /v1/obligations/apply, /v1/token/inspect, /v1/info
 *   admin key  /v1/admin/* and issuing a root token without an OIDC ID token
 * /v1/token needs no key for token exchange (holding the parent token is the
 * authority) or for issuance backed by a verified OIDC ID token.
 * TLS is not terminated here: bind to loopback or put it behind a mesh.
 *
 * Two ways to run it:
 *   Server::serve()   `smartdelegate-php serve`: one PHP CLI process, one
 *                     engine, plain sockets. Requests are answered one at a
 *                     time; connections are multiplexed, so a slow client
 *                     does not hold up the others.
 *   Server::handle()  one request -> (status, body); used by serve() and by
 *                     public/index.php under php-fpm, Apache or `php -S`.
 */
final class Server
{
    public const MAX_BODY = 8 * 1024 * 1024;
    private const MAX_HEADER = 65536;
    private const MAX_CONNECTIONS = 256;
    private const IDLE_SECONDS = 30;

    /** "METHOD path" => [operation, key kind] */
    private const ROUTES = [
        'GET /v1/info' => ['info', 'pep'],
        'POST /v1/authorize' => ['authorize', 'pep'],
        'POST /v1/filter' => ['filter', 'pep'],
        'POST /v1/explain' => ['explain', 'pep'],
        'POST /v1/obligations/apply' => ['apply_obligations', 'pep'],
        'POST /v1/token/inspect' => ['inspect_token', 'pep'],
        'POST /v1/admin/revoke' => ['revoke', 'admin'],
        'POST /v1/admin/approve' => ['approve', 'admin'],
        'POST /v1/admin/reload' => ['reload', 'admin'],
        'GET /v1/admin/approvals' => ['approvals', 'admin'],
        'GET /v1/admin/audit/verify' => ['audit_verify', 'admin'],
        'GET /v1/admin/audit/tail' => ['audit_tail', 'admin'],
    ];

    private const REASONS = [200 => 'OK', 400 => 'Bad Request', 401 => 'Unauthorized', 404 => 'Not Found', 408 => 'Request Timeout',
        431 => 'Request Header Fields Too Large', 501 => 'Not Implemented'];

    /** The message that refuses to start a server without usable keys, or null. */
    public static function keyProblem(string $adminKey, string $pepKey): ?string
    {
        if (strlen($adminKey) < 16 || strlen($pepKey) < 16) {
            return 'smartdelegate: serve needs admin_key and pep_key (16+ characters) in the config or SMARTDELEGATE_ADMIN_KEY / SMARTDELEGATE_PEP_KEY';
        }
        return null;
    }

    private static function fail(int $status, string $code, string $message): array
    {
        return [$status, new JsonObject(['ok' => false, 'error' => new JsonObject(['code' => $code, 'message' => $message])])];
    }

    /**
     * One request. Only GET and POST reach this.
     *
     * @param string      $target        the request target as sent: path and optional ?query, not decoded
     * @param string|null $authorization the Authorization header
     * @param string      $rawBody       the body of a POST
     * @param string|null $bodyError     set when the body could not be read ("bad Content-Length", "request body is too large")
     * @return array{int,JsonObject} HTTP status and JSON body
     */
    public static function handle(Engine $engine, string $adminKey, string $pepKey, string $method, string $target,
        ?string $authorization, string $rawBody = '', ?string $bodyError = null): array
    {
        $q = strpos($target, '?');
        $path = $q === false ? $target : substr($target, 0, $q);
        $query = $q === false ? '' : substr($target, $q + 1);
        if ($path === '/healthz') {
            return [200, new JsonObject(['ok' => true])];
        }
        $body = new JsonObject();
        if ($method === 'POST') {
            $err = $bodyError;
            if ($err === null && trim($rawBody, " \t\n\r\x0b\x0c") !== '') {
                try {
                    $body = Json::decodeBytes($rawBody);
                } catch (JsonError) {
                    $err = 'body is not JSON';
                }
            }
            if ($err !== null) {
                return self::fail(400, 'invalid_input', $err);
            }
        }
        unset($rawBody);
        $h = $authorization ?? '';
        $key = str_starts_with($h, 'Bearer ') ? Json::pyStrip(substr($h, 7)) : '';
        $isAdmin = hash_equals($adminKey, $key);
        $isPep = $isAdmin || hash_equals($pepKey, $key);
        if ($method === 'POST' && $path === '/v1/token') {
            if ($body instanceof JsonObject && $body->has('subject_token')) {
                $op = 'exchange_token';
                $allowed = true;
            } elseif ($body instanceof JsonObject && $body->has('id_token')) {
                $body->remove('user');   // identity comes from the ID token alone
                $op = 'issue_token';
                $allowed = true;
            } else {
                $op = 'issue_token';
                $allowed = $isAdmin;
            }
        } elseif (isset(self::ROUTES["$method $path"])) {
            [$op, $need] = self::ROUTES["$method $path"];
            $allowed = $need === 'admin' ? $isAdmin : $isPep;
            if ($op === 'audit_tail') {
                $n = '20';
                foreach (explode('&', $query) as $kv) {
                    if (str_starts_with($kv, 'n=')) {
                        $n = substr($kv, 2);
                        break;
                    }
                }
                $body = new JsonObject(['n' => ctype_digit($n) ? Num::parse($n) : 20]);
            }
        } else {
            return self::fail(404, 'not_found', 'no such endpoint');
        }
        if (!$allowed) {
            return self::fail(401, 'unauthorized', 'missing or wrong API key');
        }
        $result = $engine->callOwned($op, $body);
        return [$result->get('ok') === true ? 200 : 400, $result];
    }

    /** The response body as the reference writes it (json.dumps defaults). */
    public static function encode(JsonObject $body): string
    {
        try {
            return Json::encode($body);
        } catch (JsonError) {
            return Json::encode((new EngineError('internal', 'the result has no JSON form'))->toJson());
        }
    }

    /** "host:port" -> [host, port]; the host defaults to 127.0.0.1. */
    public static function listenAddress(string $text): array
    {
        $i = strrpos($text, ':');
        $host = $i === false ? '' : substr($text, 0, $i);
        $port = $i === false ? $text : substr($text, $i + 1);
        if (!ctype_digit($port) || (int) $port > 65535) {
            throw new \RuntimeException("--listen needs host:port, got '$text'");
        }
        return [$host !== '' ? $host : '127.0.0.1', (int) $port];
    }

    /**
     * Listen and answer until the process is stopped. Prints one line to
     * stderr once the socket is bound (port 0 picks a free port):
     *
     *     smartdelegate daemon listening on http://127.0.0.1:8181
     *
     * @return int exit status
     */
    public static function serve(Engine $engine, string $listen, string $adminKey, string $pepKey): int
    {
        $problem = self::keyProblem($adminKey, $pepKey);
        if ($problem !== null) {
            fwrite(STDERR, $problem . "\n");
            return 1;
        }
        [$host, $port] = self::listenAddress($listen);
        $ctx = stream_context_create(['socket' => ['backlog' => 128, 'tcp_nodelay' => true]]);
        $server = @stream_socket_server("tcp://$host:$port", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
        if ($server === false) {
            fwrite(STDERR, "smartdelegate: cannot listen on $host:$port: $errstr\n");
            return 1;
        }
        stream_set_blocking($server, false);
        // one request may hold several megabytes of JSON; running out of memory would end the daemon
        $limit = ini_get('memory_limit');
        if ($limit !== false && $limit !== '-1' && self::bytes($limit) < (1 << 30)) {
            @ini_set('memory_limit', '1G');
        }
        $stop = false;
        if (function_exists('pcntl_async_signals') && function_exists('pcntl_signal')) {
            pcntl_async_signals(true);
            foreach ([SIGINT, SIGTERM] as $sig) {
                pcntl_signal($sig, static function () use (&$stop): void {
                    $stop = true;
                });
            }
        }
        fwrite(STDERR, 'smartdelegate daemon listening on http://' . stream_socket_get_name($server, false) . "\n");

        /** @var array<int,array{sock:resource,in:string,out:?string,seen:int,head:?array,closing:bool}> $conns */
        $conns = [];
        while (!$stop) {
            $read = count($conns) < self::MAX_CONNECTIONS ? [$server] : [];
            $write = [];
            foreach ($conns as $c) {
                if ($c['out'] !== null) {
                    $write[] = $c['sock'];
                } else {
                    $read[] = $c['sock'];
                }
            }
            $except = null;
            $n = $read || $write ? @stream_select($read, $write, $except, 1) : (sleep(1) ?: 0);
            if ($n === false) {
                if ($stop) {
                    break;
                }
                usleep(10000);   // interrupted by a signal
                continue;
            }
            $now = time();
            foreach ($read as $sock) {
                if ($sock === $server) {
                    while (count($conns) < self::MAX_CONNECTIONS && ($client = @stream_socket_accept($server, 0)) !== false) {
                        stream_set_blocking($client, false);
                        $conns[(int) $client] = ['sock' => $client, 'in' => '', 'out' => null, 'seen' => $now, 'head' => null, 'closing' => false];
                    }
                    continue;
                }
                $id = (int) $sock;
                $chunk = @fread($sock, 262144);
                if ($chunk === false || ($chunk === '' && feof($sock))) {
                    fclose($sock);
                    unset($conns[$id]);
                    continue;
                }
                if ($chunk === '' || $conns[$id]['closing']) {
                    continue;   // closing: the response is out; whatever else the client sends is discarded
                }
                $conns[$id]['in'] .= $chunk;
                $conns[$id]['seen'] = $now;
                self::advance($conns[$id], $engine, $adminKey, $pepKey);
            }
            foreach ($write as $sock) {
                $id = (int) $sock;
                if (!isset($conns[$id]) || $conns[$id]['out'] === null) {
                    continue;
                }
                $sent = @fwrite($sock, $conns[$id]['out']);
                if ($sent === false || ($sent === 0 && feof($sock))) {
                    fclose($sock);
                    unset($conns[$id]);
                    continue;
                }
                if ($sent > 0) {
                    $conns[$id]['seen'] = $now;
                    $conns[$id]['out'] = substr($conns[$id]['out'], $sent);
                }
                if ($conns[$id]['out'] === '') {
                    // Half-close and wait for the client to close. Closing at once, with part of
                    // a request still unread, would reset the connection and could lose the response.
                    @stream_socket_shutdown($sock, STREAM_SHUT_WR);
                    $conns[$id]['out'] = null;
                    $conns[$id]['closing'] = true;
                }
            }
            foreach ($conns as $id => $c) {
                if ($now - $c['seen'] > ($c['closing'] ? 2 : self::IDLE_SECONDS)) {
                    fclose($c['sock']);
                    unset($conns[$id]);
                }
            }
        }
        foreach ($conns as $c) {
            fclose($c['sock']);
        }
        fclose($server);
        return 0;
    }

    private static function bytes(string $ini): int
    {
        $n = (int) $ini;
        return match (strtolower(substr(trim($ini), -1))) {
            'g' => $n << 30,
            'm' => $n << 20,
            'k' => $n << 10,
            default => $n,
        };
    }

    /** Move one connection forward: parse what has arrived and, when the request is complete, queue the response. */
    private static function advance(array &$c, Engine $engine, string $adminKey, string $pepKey): void
    {
        if ($c['head'] === null) {
            if (preg_match('/\r?\n\r?\n/', $c['in'], $m, PREG_OFFSET_CAPTURE) !== 1) {
                if (strlen($c['in']) > self::MAX_HEADER) {
                    $c['out'] = self::response(431, self::fail(431, 'invalid_input', 'request headers are too large')[1]);
                }
                return;
            }
            $headText = substr($c['in'], 0, $m[0][1]);
            $c['in'] = substr($c['in'], $m[0][1] + strlen($m[0][0]));
            $lines = preg_split('/\r?\n/', ltrim($headText, "\r\n"));
            $parts = explode(' ', trim((string) array_shift($lines)));
            if (count($parts) !== 3 || !str_starts_with($parts[2], 'HTTP/1.')) {
                $c['out'] = self::response(400, self::fail(400, 'invalid_input', 'bad request line')[1]);
                return;
            }
            $headers = [];
            foreach ($lines as $line) {
                $i = strpos($line, ':');
                if ($i !== false) {
                    $name = strtolower(trim(substr($line, 0, $i)));
                    $headers[$name] ??= trim(substr($line, $i + 1));   // the first of a repeated header, as in the reference
                }
            }
            $head = ['method' => $parts[0], 'target' => $parts[1], 'auth' => $headers['authorization'] ?? null, 'need' => 0, 'error' => null];
            if ($head['method'] !== 'GET' && $head['method'] !== 'POST') {
                $c['out'] = self::response(501, self::fail(501, 'unsupported_method', "Unsupported method ('{$head['method']}')")[1]);
                return;
            }
            $path = explode('?', $head['target'], 2)[0];
            if ($head['method'] === 'POST' && $path !== '/healthz') {
                $cl = $headers['content-length'] ?? '';
                if ($cl !== '' && preg_match('/^\s*[-+]?[0-9]+\s*$/', $cl) !== 1) {
                    $head['error'] = 'bad Content-Length';
                } elseif ($cl !== '') {
                    $len = Num::parse(ltrim(trim($cl), '+'));
                    if (Num::cmp($len, self::MAX_BODY) > 0) {
                        $head['error'] = 'request body is too large';
                    } elseif (Num::cmp($len, 0) > 0) {
                        $head['need'] = $len;
                    }
                }
                if ($head['error'] === null && $head['need'] > strlen($c['in']) && strtolower($headers['expect'] ?? '') === '100-continue') {
                    @fwrite($c['sock'], "HTTP/1.1 100 Continue\r\n\r\n");
                }
            }
            $c['head'] = $head;
        }
        $head = $c['head'];
        if ($head['error'] === null && strlen($c['in']) < $head['need']) {
            return;   // the rest of the body has not arrived yet
        }
        $raw = $head['error'] === null ? substr($c['in'], 0, $head['need']) : '';
        $c['in'] = '';
        try {
            [$status, $body] = self::handle($engine, $adminKey, $pepKey, $head['method'], $head['target'], $head['auth'], $raw, $head['error']);
        } catch (\Throwable $e) {
            [$status, $body] = [400, (new EngineError('internal', get_class($e) . ': ' . $e->getMessage()))->toJson()];
        }
        $c['out'] = self::response($status, $body);
    }

    private static function response(int $status, JsonObject $body): string
    {
        $raw = self::encode($body);
        return 'HTTP/1.1 ' . $status . ' ' . (self::REASONS[$status] ?? 'Error') . "\r\n"
            . "Server: smartdelegate\r\n"
            . 'Date: ' . gmdate('D, d M Y H:i:s') . " GMT\r\n"
            . "Content-Type: application/json\r\n"
            . 'Content-Length: ' . strlen($raw) . "\r\n"
            . "Connection: close\r\n\r\n" . $raw;
    }
}
