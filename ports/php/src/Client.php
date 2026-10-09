<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * Thin REST client for `smartdelegate serve` (any port's daemon). Uses PHP's
 * http stream wrapper: no curl, no Composer packages, and no environment
 * proxy (decision traffic is never routed through http_proxy).
 *
 *     $iam = new Client('http://127.0.0.1:8181', pepKey: '...', adminKey: '...');
 *     $r = $iam->call('authorize', ['token' => $t, 'action' => 'read', 'resource' => ['path' => 'crm.customer', 'id' => 'c-1']]);
 */
final class Client
{
    /** op => [method, path, key kind] */
    private const ROUTES = [
        'authorize' => ['POST', '/v1/authorize', 'pep'],
        'filter' => ['POST', '/v1/filter', 'pep'],
        'explain' => ['POST', '/v1/explain', 'pep'],
        'apply_obligations' => ['POST', '/v1/obligations/apply', 'pep'],
        'inspect_token' => ['POST', '/v1/token/inspect', 'pep'],
        'info' => ['GET', '/v1/info', 'pep'],
        'exchange_token' => ['POST', '/v1/token', null],
        'issue_token' => ['POST', '/v1/token', 'admin'],
        'revoke' => ['POST', '/v1/admin/revoke', 'admin'],
        'approve' => ['POST', '/v1/admin/approve', 'admin'],
        'reload' => ['POST', '/v1/admin/reload', 'admin'],
        'approvals' => ['GET', '/v1/admin/approvals', 'admin'],
        'audit_verify' => ['GET', '/v1/admin/audit/verify', 'admin'],
        'audit_tail' => ['GET', '/v1/admin/audit/tail', 'admin'],
    ];

    private string $url;
    /** @var array{pep:?string,admin:?string} */
    private array $keys;

    public function __construct(string $url, ?string $pepKey = null, ?string $adminKey = null, private float $timeout = 10.0)
    {
        $this->url = rtrim($url, '/');
        $this->keys = ['pep' => ($pepKey !== null && $pepKey !== '') ? $pepKey : $adminKey, 'admin' => $adminKey];
    }

    /**
     * The same contract as Engine::call(): JSON in, JSON out, the result as
     * an array whose nested objects are JsonObject. As there, `[]` as the
     * request itself is the empty object.
     *
     * @throws EngineError `daemon_unreachable`: an unreachable decision point is never an allow
     */
    public function call(string $op, mixed $payload = null): array
    {
        if (!isset(self::ROUTES[$op])) {
            return self::error('unknown_op', "no operation named '$op'");
        }
        [$method, $path, $keyKind] = self::ROUTES[$op];
        try {
            $payload = Json::fromNative($payload === null || $payload === [] ? new JsonObject() : $payload);
            $body = Json::encode($payload);
        } catch (JsonError $e) {
            return self::error('invalid_input', 'the request is not JSON data: ' . $e->getMessage());
        }
        $obj = $payload instanceof JsonObject ? $payload : new JsonObject();
        if ($op === 'audit_tail' && $obj->has('n') && Num::isInt($obj->get('n'))) {
            $path .= '?n=' . Num::str($obj->get('n'));
        }
        $headers = ['Content-Type: application/json', 'Accept: application/json'];
        $key = $keyKind !== null ? $this->keys[$keyKind] : null;
        if ($op === 'issue_token' && Json::truthy($obj->get('id_token'))) {
            $key = null;   // the ID token is the credential
        }
        if ($key !== null && $key !== '') {
            $headers[] = 'Authorization: Bearer ' . $key;
        }
        $http = ['method' => $method, 'header' => implode("\r\n", $headers), 'timeout' => $this->timeout, 'ignore_errors' => true,
            'follow_location' => 0, 'protocol_version' => 1.1, 'user_agent' => 'smartdelegate-php/' . Engine::VERSION];
        if ($method === 'POST') {
            $http['content'] = $body;
        }
        $text = @file_get_contents($this->url . $path, false, stream_context_create(['http' => $http]));
        $responseHeaders = function_exists('http_get_last_response_headers') ? http_get_last_response_headers() : ($http_response_header ?? null);
        if ($text === false || !$responseHeaders) {
            throw new EngineError('daemon_unreachable', (error_get_last()['message'] ?? 'no response') . ' (' . $this->url . ')');
        }
        $status = preg_match('{^HTTP/\S+\s+(\d{3})}', (string) $responseHeaders[0], $m) === 1 ? (int) $m[1] : 0;
        try {
            $result = Json::decodeBytes($text);
        } catch (JsonError) {
            $result = null;
        }
        if (!$result instanceof JsonObject) {
            return self::error('http_error', "HTTP $status");
        }
        return $result->m;
    }

    private static function error(string $code, string $message): array
    {
        return ['ok' => false, 'error' => new JsonObject(['code' => $code, 'message' => $message])];
    }
}
