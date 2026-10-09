<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * The engine: one object that issues and exchanges capability tokens, answers
 * authorization requests, applies field obligations and writes the audit log.
 * A port of the Python reference (src/sf_smartdelegate/engine.py);
 * spec/conformance/vectors defines its behaviour.
 *
 * Decision order for `authorize` / `filter` (first failure wins, default deny):
 *   1. token: signature, issuer, expiry, revocation (own id and every ancestor)
 *   2. catalog: the resource path must be known
 *   3. tenant: token tenant must equal the resource tenant, when both exist
 *   4. capability: the token's `cap` must cover the action and the resource
 *   5. policy: Cedar, forbid overrides permit, an erroring forbid denies
 *   6. obligations from the permits that decided: row filter, rate limit
 *   7. budget: `context.spend` against every token in the delegation chain
 *   8. human approval, last so nobody is asked to approve a doomed request
 *   9. fields: capability deny lists, then policy per field (default deny)
 *  10. strict mode (inputs): any denied field present in the data denies
 *
 * JSON in, JSON out. Inside the engine a JSON object is a JsonObject and a
 * JSON list is a PHP list array; see Json::fromNative() for how native PHP
 * input is read (an empty PHP array is an empty LIST).
 */
final class Engine
{
    public const VERSION = '0.3.0';
    public const IMPLEMENTATION = 'php';

    private string $bundleDir;
    private ?string $stateDir;
    private string $issuer;
    private bool $shadow;
    private bool $trustCallerChain;
    private bool $allowTestClock;
    private ?string $bundlePublicKey;
    private int|BigInt $maxTtl;
    private int|BigInt $defaultTtl;
    private int|BigInt $maxDepth;
    private int|BigInt $approvalTtl;
    private bool $requireRole;
    /** @var array{issuer:string,audience:string,jwks:mixed,user_claim:string,groups_claim:?string,group_type:string,group_map:?JsonObject,jwks_file:?string}|null */
    private ?array $idp = null;
    private Bundle $bundle;
    private Keys $keys;
    private State $state;
    private ?Audit $audit = null;
    /** @var resource|null */
    private $lockFile = null;
    /**
     * Rate-limit windows: key => timestamps of allowed calls. In memory only,
     * as in the reference: per engine object, gone when the process ends.
     *
     * @var array<string,list<int|BigInt>>
     */
    private array $rate = [];
    private int $counter = 0;
    /** The request being answered came in as native PHP data (call()), not as JSON text. Only shapes a hint in one message. */
    private bool $native = false;

    // ---- small helpers ---------------------------------------------------------

    private static function s(mixed $v, string $key): ?string
    {
        $x = $v instanceof JsonObject ? $v->get($key) : null;
        return is_string($x) && $x !== '' ? $x : null;
    }

    private static function req(mixed $v, string $key): string
    {
        $x = self::s($v, $key);
        if ($x === null) {
            throw new EngineError('invalid_input', "'$key' is required");
        }
        return $x;
    }

    private static function int(JsonObject $v, string $key, int|BigInt $default): int|BigInt
    {
        $x = $v->get($key);
        return Num::isInt($x) ? $x : $default;
    }

    private static function entity(string $type, string $id): Entity
    {
        if (!Cedar::validType($type)) {
            throw new EngineError('invalid_input', "'$type' is not a valid entity type");
        }
        return new Entity($type, $id);
    }

    /** @return array{mixed,bool} value, found */
    private static function lookup(mixed $root, string $dotted): array
    {
        $cur = $root;
        foreach (explode('.', $dotted) as $part) {
            if (!$cur instanceof JsonObject || !$cur->has($part)) {
                return [null, false];
            }
            $cur = $cur->get($part);
        }
        return [$cur, true];
    }

    /**
     * `column == context.key`, `column == "literal"`, `column == 42`, joined by `&&`.
     *
     * @return list<JsonObject>
     */
    private static function parseRowFilter(mixed $expr, JsonObject $ctx): array
    {
        if (!is_string($expr)) {
            throw new \TypeError('a row_filter annotation must be a string');
        }
        $out = [];
        foreach (explode('&&', $expr) as $clause) {
            $parts = array_map([Json::class, 'pyStrip'], explode('==', $clause, 2));
            if (count($parts) !== 2 || preg_match('/^[A-Za-z0-9_]+$/D', $parts[0]) !== 1) {
                throw new Deny('policy_error', "row_filter clause '" . Json::pyStrip($clause) . "' is not `column == value`");
            }
            $rhs = $parts[1];
            if (str_starts_with($rhs, 'context.')) {
                [$value, $found] = self::lookup($ctx, substr($rhs, 8));
                if (!$found || $value instanceof JsonObject || is_array($value) || is_float($value) || $value === null) {
                    throw new Deny('obligation_unresolved', "row filter needs $rhs, which the request did not supply");
                }
            } elseif (strlen($rhs) >= 2 && $rhs[0] === '"' && $rhs[strlen($rhs) - 1] === '"') {
                $value = substr($rhs, 1, -1);
            } elseif (preg_match('/^-?[0-9]+$/D', $rhs) === 1) {
                $value = Num::parse($rhs);
            } else {
                throw new Deny('policy_error', "row_filter value '$rhs' is not context.<key>, a quoted string or an integer");
            }
            $out[] = new JsonObject(['column' => $parts[0], 'op' => 'eq', 'value' => $value]);
        }
        return $out;
    }

    /** "<count>/<seconds>" -> [count, seconds], or null. */
    private static function parseRate(mixed $expr): ?array
    {
        if (!Json::truthy($expr)) {
            $expr = '';
        }
        if (!is_string($expr)) {
            throw new \TypeError('a rate_limit annotation must be a string');
        }
        if (preg_match('/^\s*([0-9]+)\s*\/\s*([0-9]+)\s*$/', $expr, $m) !== 1) {
            return null;
        }
        $window = Num::parse($m[2]);
        if (Num::cmp($window, 0) <= 0) {
            return null;
        }
        return [Num::parse($m[1]), $window];
    }

    // ---- construction ----------------------------------------------------------

    /**
     * @param array|JsonObject|\stdClass $config {"bundle_dir", "state_dir", "issuer", "mode", ...}; see spec/API.md
     * @throws EngineError when the configuration, the bundle or the state directory is unusable
     */
    public function __construct(mixed $config)
    {
        try {
            $c = Json::fromNative($config);
        } catch (JsonError $e) {
            throw new EngineError('invalid_input', 'config: ' . $e->getMessage());
        }
        if (!$c instanceof JsonObject) {
            throw new EngineError('invalid_input', 'config must be an object');
        }
        $this->bundleDir = self::req($c, 'bundle_dir');
        $this->stateDir = self::s($c, 'state_dir');
        $this->issuer = self::s($c, 'issuer') ?? 'smartdelegate://local';
        $mode = self::s($c, 'mode') ?? 'enforce';
        if ($mode !== 'enforce' && $mode !== 'shadow') {
            throw new EngineError('invalid_config', "mode must be 'enforce' or 'shadow'");
        }
        $this->shadow = $mode === 'shadow';
        $this->trustCallerChain = $c->get('trust_caller_chain') === true;
        $this->allowTestClock = $c->get('allow_test_clock') === true;
        $this->bundlePublicKey = self::s($c, 'bundle_public_key');
        $this->maxTtl = self::int($c, 'max_ttl', 3600);
        $this->defaultTtl = self::int($c, 'default_ttl', 900);
        $this->maxDepth = self::int($c, 'max_depth', 4);
        $this->approvalTtl = self::int($c, 'approval_ttl', 900);
        $this->requireRole = $c->get('require_role') === true;
        $idp = $c->get('idp');
        if ($idp instanceof JsonObject) {
            $jwks = $idp->get('jwks');
            if (!$jwks instanceof JsonObject) {
                $file = self::req($idp, 'jwks_file');
                $text = is_file($file) ? @file_get_contents($file) : false;
                if ($text === false) {
                    throw new EngineError('invalid_config', "jwks_file: cannot read $file");
                }
                try {
                    $jwks = Json::decode($text);
                } catch (JsonError $e) {
                    throw new EngineError('invalid_config', 'jwks_file: ' . $e->getMessage());
                }
            }
            $gmap = $idp->get('group_map');
            if ($gmap !== null) {
                $ok = $gmap instanceof JsonObject;
                foreach ($ok ? $gmap->m : [] as $x) {
                    $ok = $ok && is_string($x);
                }
                if (!$ok) {
                    throw new EngineError('invalid_config', 'idp.group_map must map a claim value to a group id');
                }
            }
            $gtype = self::s($idp, 'group_type') ?? 'Group';
            if (!Cedar::validType($gtype)) {
                throw new EngineError('invalid_config', 'idp.group_type is not a valid entity type');
            }
            $this->idp = ['issuer' => self::req($idp, 'issuer'), 'audience' => self::req($idp, 'audience'), 'jwks' => $jwks,
                'user_claim' => self::s($idp, 'user_claim') ?? 'sub', 'groups_claim' => self::s($idp, 'groups_claim'),
                'group_type' => $gtype, 'group_map' => $gmap,
                'jwks_file' => $idp->get('jwks') instanceof JsonObject ? null : self::s($idp, 'jwks_file')];
        }

        $this->bundle = new Bundle($this->bundleDir, $this->bundlePublicKey);
        if ($this->stateDir !== null && !is_dir($this->stateDir) && !@mkdir($this->stateDir, 0777, true) && !is_dir($this->stateDir)) {
            throw new EngineError('state_io', $this->stateDir . ': ' . (error_get_last()['message'] ?? 'cannot create the directory'));
        }

        $private = null;
        if ($c->get('verify_only') === true) {
            // verifies tokens issued elsewhere; cannot issue
        } elseif (self::s($c, 'signing_key') !== null) {
            $private = $c->get('signing_key');
        } elseif ($this->stateDir !== null) {
            $private = $this->stateSigningKey();
        } else {
            $private = Bundle::keygen()[0];
        }
        $trusted = [];
        $tk = $c->get('trusted_keys');
        if (Json::truthy($tk)) {
            if (is_string($tk)) {
                throw new EngineError('crypto', 'public key is not base64 of 32 raw Ed25519 bytes');
            }
            if (!is_array($tk) && !$tk instanceof JsonObject) {
                throw new EngineError('invalid_config', 'trusted_keys must be a list of public keys');
            }
            foreach (is_array($tk) ? $tk : $tk->keys() as $k) {
                if (is_string($k)) {
                    $trusted[] = $k;
                }
            }
        }
        $this->keys = new Keys($private, $trusted);

        if ($this->stateDir !== null) {
            $f = @fopen($this->stateDir . '/lock', 'a+b');
            if ($f === false) {
                throw new EngineError('state_io', $this->stateDir . '/lock: ' . (error_get_last()['message'] ?? 'cannot open'));
            }
            $this->lockFile = $f;
        }
        try {
            $this->lock();
            try {
                $this->state = new State($this->stateDir);
                if ($this->stateDir !== null && $c->get('audit', true) !== false) {
                    $this->audit = new Audit($this->stateDir . '/audit.jsonl');
                }
            } finally {
                $this->unlock();
            }
        } catch (\Throwable $e) {
            $this->close();
            throw $e;
        }
    }

    /**
     * The key in the state directory; created (mode 0600) the first time.
     *
     * Safe when several processes start on an empty state directory at once.
     * The key is written to a private temporary file and then given its name
     * with link(), which fails if the name exists: the key file therefore
     * appears complete or not at all, and exactly one process creates it.
     * Every other process reads that file. Another port may create the file
     * first and fill it a moment later, so an empty key file is waited for;
     * it is never taken to mean "no signing key".
     */
    private function stateSigningKey(): string
    {
        $kp = $this->stateDir . '/signing_key.pk8.b64';
        clearstatcache(true, $kp);
        if (!file_exists($kp)) {
            [$private, $public] = Bundle::keygen();
            $tmp = $kp . '.' . getmypid() . '.' . bin2hex(random_bytes(6)) . '.tmp';
            $old = umask(0177);
            $f = @fopen($tmp, 'x');
            umask($old);
            if ($f === false) {
                throw new EngineError('state_io', "$kp: " . (error_get_last()['message'] ?? 'cannot create the signing key'));
            }
            @chmod($tmp, 0600);
            $ok = fwrite($f, $private) === strlen($private) && fflush($f);
            fclose($f);
            $created = $ok && @link($tmp, $kp);
            $why = error_get_last()['message'] ?? 'cannot create the signing key';
            @unlink($tmp);
            if ($created) {
                if (@file_put_contents($this->stateDir . '/signing_key.pub.b64', $public) === false) {
                    throw new EngineError('state_io', "$kp: cannot write the public key");
                }
                return $private;
            }
            clearstatcache(true, $kp);
            if (!$ok || !file_exists($kp)) {
                throw new EngineError('state_io', "$kp: $why");
            }
            // another process created the key between the check and now: use theirs
        }
        $deadline = microtime(true) + 30;
        do {
            $text = @file_get_contents($kp);
            if ($text === false) {
                throw new EngineError('state_io', "$kp: " . (error_get_last()['message'] ?? 'cannot read the signing key'));
            }
            if (Json::pyStrip($text) !== '') {
                return $text;
            }
            usleep(10000);   // created by another process and not written yet
        } while (microtime(true) < $deadline);
        throw new EngineError('state_io', "$kp: the signing key file is empty");
    }

    public function __destruct()
    {
        $this->close();
    }

    // ---- plumbing ----------------------------------------------------------------

    /** flock(2) on <state_dir>/lock: the same lock the Python reference and the Rust port take. */
    private function lock(): void
    {
        if ($this->lockFile !== null && !@flock($this->lockFile, LOCK_EX)) {
            throw new EngineError('state_io', 'cannot lock the state directory');
        }
    }

    private function unlock(): void
    {
        if ($this->lockFile !== null) {
            @flock($this->lockFile, LOCK_UN);
        }
    }

    /** Release the lock file. The engine is not meant to be used afterwards. */
    public function close(): void
    {
        if ($this->lockFile !== null) {
            @fclose($this->lockFile);
            $this->lockFile = null;
        }
    }

    /**
     * JSON in, JSON out. Never throws: errors come back as
     * ["ok" => false, "error" => {"code", "message", "rule"}].
     *
     * @param mixed $payload the request: a PHP array, a JsonObject or a stdClass.
     *                       A PHP array cannot say whether it is `{}` or `[]` when
     *                       it is empty. As the request itself, `[]` is taken to be
     *                       the empty object, so `call('info', [])` works. Anywhere
     *                       inside the request an empty PHP array is an empty LIST:
     *                       write `new \stdClass` (or `new JsonObject`) for `{}`.
     * @return array<string,mixed> the result object. Nested JSON objects are
     *                             JsonObject (readable as arrays), nested lists are PHP lists
     */
    public function call(string $op, mixed $payload = []): array
    {
        return $this->run($op, $payload === [] ? new JsonObject() : $payload, false)->m;
    }

    /** As call(), with the request and the result as JSON text. */
    public function callJson(string $op, string $json): string
    {
        try {
            $payload = Json::decodeBytes($json);
        } catch (JsonError $e) {
            return Json::compact((new EngineError('invalid_input', 'the request is not JSON: ' . $e->getMessage()))->toJson());
        }
        try {
            return Json::compact($this->run($op, $payload, true));
        } catch (\Throwable $e) {
            return Json::compact((new EngineError('internal', 'the result has no JSON form'))->toJson());
        }
    }

    /**
     * @internal For callers inside this package (the REST server) that hand
     * over a tree made by Json::decode() and drop both it and the result
     * straight away: no defensive copies are made.
     */
    public function callOwned(string $op, mixed $model): JsonObject
    {
        return $this->run($op, $model, true);
    }

    private function run(string $op, mixed $payload, bool $owned): JsonObject
    {
        try {
            try {
                // a private copy: the engine may change it, and the caller may change theirs
                $payload = $owned ? $payload : Json::fromNative($payload);
            } catch (JsonError $e) {
                if ($e->getMessage() === 'nested too deeply') {
                    throw new EngineError('invalid_input', 'the request is nested too deeply');
                }
                throw new EngineError('invalid_input', 'the request is not JSON data: ' . $e->getMessage());
            }
            $this->lock();
            try {
                $this->native = !$owned;
                if (!$payload instanceof JsonObject) {
                    throw new EngineError('invalid_input', 'the request body must be a JSON object');
                }
                $this->state->refresh();
                $out = $this->dispatch($op, $payload);
                $out->set('ok', true);
                return $owned ? $out : Json::deepCopy($out);   // the caller must not be handed the engine's own state
            } finally {
                $this->unlock();
            }
        } catch (EngineError $e) {
            return $e->toJson();
        } catch (\Throwable $e) {   // a bug must surface as a refusal, never as an allow or a crash
            return (new EngineError('internal', get_class($e) . ': ' . $e->getMessage()))->toJson();
        }
    }

    private function dispatch(string $op, JsonObject $i): JsonObject
    {
        if ($op === 'authorize') {
            return $this->decide($i, false);
        }
        if ($op === 'filter') {
            return $this->decide($i, true);
        }
        if ($op === 'explain') {
            $j = $i->copy();
            $j->set('explain', true);
            $j->set('dry_run', true);
            return $this->decide($j, $i->has('data'));
        }
        if ($op === 'issue_token') {
            return $this->issueToken($i);
        }
        if ($op === 'exchange_token') {
            return $this->exchangeToken($i);
        }
        if ($op === 'inspect_token') {
            return $this->inspectToken($i);
        }
        if ($op === 'apply_obligations') {
            return $this->applyObligations($i);
        }
        if ($op === 'revoke') {
            return $this->revoke($i);
        }
        if ($op === 'approve') {
            return $this->approve($i);
        }
        if ($op === 'approvals') {
            return new JsonObject(['pending' => $this->state->section('pending'), 'granted' => $this->state->section('approvals')]);
        }
        if ($op === 'audit_verify') {
            if ($this->audit === null) {
                throw new EngineError('no_audit', 'this engine has no audit log (no state_dir, or audit is off)');
            }
            clearstatcache(true, $this->audit->path);
            if (!file_exists($this->audit->path)) {
                return new JsonObject(['records' => 0, 'head' => Audit::GENESIS]);
            }
            return Audit::verify($this->audit->path);
        }
        if ($op === 'audit_tail') {
            if ($this->audit === null) {
                throw new EngineError('no_audit', 'this engine has no audit log');
            }
            return new JsonObject(['records' => Audit::tail($this->audit->path, self::int($i, 'n', 20))]);
        }
        if ($op === 'info') {
            return $this->infoDict();
        }
        if ($op === 'reload') {
            // a bundle that fails to load leaves the old one in force
            $newBundle = new Bundle($this->bundleDir, $this->bundlePublicKey);
            // the provider's signing keys are re-read too, so a key rotation
            // needs a reload, not a restart; a file that fails to load leaves
            // the old keys (and the old bundle) in force
            if ($this->idp !== null && $this->idp['jwks_file'] !== null) {
                $text = is_file($this->idp['jwks_file']) ? @file_get_contents($this->idp['jwks_file']) : false;
                try {
                    $jwks = $text === false ? null : Json::decode($text);
                } catch (JsonError $e) {
                    throw new EngineError('invalid_config', 'jwks_file: ' . $e->getMessage());
                }
                if (!$jwks instanceof JsonObject || !is_array($jwks->get('keys'))) {
                    throw new EngineError('invalid_config', 'jwks_file: ' . ($text === false ? 'cannot read the file' : 'expected {"keys": [...]}'));
                }
                $this->idp['jwks'] = $jwks;
            }
            $this->bundle = $newBundle;
            $this->auditAppend(new JsonObject(['event' => 'bundle_reloaded', 'policy_version' => $this->bundle->version]), time());
            return $this->infoDict();
        }
        throw new EngineError('unknown_op', "no operation named '$op'");
    }

    private function infoDict(): JsonObject
    {
        $resources = array_map('strval', array_keys($this->bundle->catalog));
        sort($resources, SORT_STRING);
        $roles = array_map('strval', array_keys($this->bundle->roles));
        sort($roles, SORT_STRING);
        return new JsonObject(['version' => self::VERSION, 'implementation' => self::IMPLEMENTATION, 'policy_version' => $this->bundle->version,
            'bundle_signed_by' => $this->bundle->signedBy, 'policies' => count($this->bundle->policies),
            'resources' => $resources, 'roles' => $roles, 'mode' => $this->shadow ? 'shadow' : 'enforce',
            'issuer' => $this->issuer, 'key_id' => $this->keys->kid, 'public_key' => $this->keys->publicB64,
            'can_issue' => $this->keys->canSign(), 'oidc' => $this->idp !== null ? $this->idp['issuer'] : null]);
    }

    private function now(JsonObject $i): int|BigInt
    {
        $n = $i->get('now');
        if ($this->allowTestClock && Num::isInt($n)) {
            return $n;
        }
        return time();
    }

    /**
     * Fail closed: when the decision cannot be recorded, the operation fails
     * and the caller gets an error instead of an allow.
     */
    private function auditAppend(JsonObject $record, int|BigInt $ts): void
    {
        if ($this->audit !== null) {
            try {
                $this->audit->append($record, $ts);
            } catch (EngineError $e) {
                throw new EngineError('audit_io', 'the decision could not be recorded, so it is refused: ' . $e->detail);
            }
        }
    }

    // ---- tokens ------------------------------------------------------------------

    /** @throws Deny; `claims` is attached when the signature was good */
    private function verifyToken(string $token, int|BigInt $now): JsonObject
    {
        try {
            $claims = $this->keys->verify($token, $this->issuer);
        } catch (TokenInvalid $e) {
            throw new Deny('token_invalid', $e->getMessage());
        }
        $d = null;
        if (!Tokens::chainOf($claims)) {
            throw new Deny('token_invalid', 'the token names no agent');
        }
        if (Num::cmp($claims->get('exp'), $now) <= 0) {
            $d = new Deny('token_expired', 'the capability token has expired');
        } elseif (Num::cmp($claims->get('iat'), Num::add($now, 60)) > 0) {
            $d = new Deny('token_invalid', 'the capability token is dated in the future');
        } else {
            $revoked = $this->state->section('revoked');
            foreach ([...$claims->get('anc'), $claims->get('jti')] as $tid) {
                if ($revoked->has($tid)) {
                    $d = new Deny('token_revoked', "token $tid in the delegation chain was revoked");
                    break;
                }
            }
            // offboarding: every token of this user issued up to the cut-off is dead
            $cutoff = $this->state->section('revoked_users')->get(Tokens::userOf($claims));
            if ($d === null && Num::isInt($cutoff) && Num::cmp($claims->get('iat'), $cutoff) <= 0) {
                $d = new Deny('token_revoked', 'every token issued for this user up to the cut-off was revoked');
            }
        }
        if ($d !== null) {
            $d->claims = $claims;
            throw $d;
        }
        return $claims;
    }

    private function iamContext(Principal $p): JsonObject
    {
        return new JsonObject([
            'user_attrs' => $this->bundle->attrs['User::' . $p->user] ?? new JsonObject(),
            'user' => new JsonObject(['__entity' => new JsonObject(['type' => 'User', 'id' => $p->user])]),
            'user_id' => $p->user,
            'chain' => $p->chain,
            'depth' => count($p->chain),
            'root_agent' => new JsonObject(['__entity' => new JsonObject(['type' => 'Agent', 'id' => $p->chain ? $p->chain[0] : ''])]),
            'tenant' => Json::truthy($p->tenant) ? $p->tenant : '',
            'task' => Json::truthy($p->task) ? $p->task : '',
            'role' => Json::truthy($p->role) ? $p->role : '',
        ]);
    }

    /**
     * The entity store this principal is judged against. A token that carries
     * live group membership replaces what entities.json says about that
     * user; everything else is unchanged.
     */
    private function storeFor(Principal $p): Store
    {
        if ($p->groups === null) {
            return $this->bundle->store;
        }
        $parents = [];
        foreach ($p->groups as $g) {
            $parents[] = new Entity($g->get('type'), $g->get('id'));
        }
        return $this->bundle->store->withParents(new Entity('User', $p->user), $parents);
    }

    /**
     * Normalise group membership supplied at issuance: names or {type, id}.
     * Groups that entities.json does not define are dropped; the result is
     * sorted and free of duplicates, so every port writes the same claim.
     *
     * @return list<JsonObject>
     */
    private function groups(mixed $raw, string $defaultType, ?JsonObject $mapping): array
    {
        if (is_string($raw)) {
            $raw = [$raw];
        }
        if (!is_array($raw)) {
            throw new EngineError('invalid_input', 'groups must be a list of group names or {type, id}');
        }
        $out = [];
        foreach ($raw as $g) {
            if (is_string($g)) {
                if ($mapping !== null) {
                    if (!$mapping->has($g)) {
                        continue;
                    }
                    $g = $mapping->get($g);
                }
                $t = $defaultType;
                $n = $g;
            } elseif ($g instanceof JsonObject && is_string($g->get('type')) && is_string($g->get('id'))) {
                $t = $g->get('type');
                $n = $g->get('id');
            } else {
                throw new EngineError('invalid_input', 'groups must be a list of group names or {type, id}');
            }
            if (Cedar::validType($t)) {
                $e = new Entity($t, $n);
                if ($this->bundle->store->contains($e)) {
                    $out[$e->key] = [$t, $n];
                }
            }
        }
        $out = array_values($out);
        usort($out, static fn (array $a, array $b): int => (strcmp($a[0], $b[0]) ?: strcmp($a[1], $b[1])) <=> 0);
        return array_map(static fn (array $x): JsonObject => new JsonObject(['type' => $x[0], 'id' => $x[1]]), $out);
    }

    /**
     * The human lends the agent one of their roles for this task. Returns the
     * capability and lifetime the token gets; throws when the human does not
     * hold the role or asks for more than the role allows.
     *
     * @return array{Cap,int|BigInt}
     */
    private function applyRole(string $name, Principal $p, ?Cap $cap, int|BigInt $ttl): array
    {
        $role = $this->bundle->roles[$name] ?? null;
        if ($role === null) {
            throw new EngineError('unknown_role', "roles.json defines no role named '$name'");
        }
        $user = new Entity('User', $p->user);
        $held = $this->storeFor($p)->ancestors($user);
        $held[$user->key] = true;
        $holds = false;
        foreach ($role->members as $m) {
            $holds = $holds || isset($held[$m->key]);
        }
        if (!$holds) {
            throw new EngineError('role_not_held', "user '{$p->user}' does not hold the role '$name'");
        }
        if ($role->agents !== null && !self::anyMatch($role->agents, $p->leaf())) {
            throw new EngineError('role_exceeded', "agent '{$p->leaf()}' may not be started in the role '$name'");
        }
        if ($role->tasks !== null && !(Json::truthy($p->task) && self::anyMatch($role->tasks, $p->task))) {
            throw new EngineError('role_exceeded', "the role '$name' covers only tasks matching: " . implode(', ', $role->tasks));
        }
        if ($cap === null) {
            $cap = Cap::fromJson($role->cap->toJson());
        } else {
            // what the role never sees, the token never sees
            $cap->denyLabels = self::sortedUnion($cap->denyLabels, $role->cap->denyLabels);
            $cap->denyFields = self::sortedUnion($cap->denyFields, $role->cap->denyFields);
            try {
                $cap->checkNarrowerThan($role->cap);
            } catch (EngineError $e) {
                throw new EngineError('role_exceeded', "more than the role '$name' allows: " . $e->detail);
            }
        }
        return [$cap, $role->maxTtl !== null ? Num::min($ttl, $role->maxTtl) : $ttl];
    }

    private static function anyMatch(array $patterns, string $s): bool
    {
        foreach ($patterns as $p) {
            if (Cap::matches($p, $s)) {
                return true;
            }
        }
        return false;
    }

    /** @return list<string> */
    private static function sortedUnion(array $a, array $b): array
    {
        $set = [];
        foreach ([...$a, ...$b] as $x) {
            $set['=' . $x] = $x;
        }
        $out = array_values($set);
        sort($out, SORT_STRING);
        return $out;
    }

    /** @return array{allow:bool,policies:list<string>,errors:list<JsonObject>,forbid_error:bool} */
    private function evaluate(Entity $principal, string $action, Entity $resource, array $ctx, Store $store): array
    {
        $r = Cedar::isAuthorized($this->bundle->policies, new Env($principal, self::entity('Action', $action), $resource, $ctx, $store));
        $errors = [];
        $forbidError = false;
        foreach ($r['errors'] as [$pid, $msg]) {
            $isForbid = !$this->bundle->policies[$pid]->permit;
            $forbidError = $forbidError || $isForbid;
            $errors[] = new JsonObject(['policy' => $pid, 'effect' => $isForbid ? 'forbid' : 'permit', 'error' => $msg]);
        }
        return ['allow' => $r['decision'] === 'allow' && !$forbidError, 'policies' => $r['reasons'], 'errors' => $errors, 'forbid_error' => $forbidError];
    }

    /**
     * Is `delegator` allowed to hand `cap` to `agent`? Governed by the same
     * policies as everything else: action "delegate" on the Agent.
     */
    private function checkDelegation(Entity $delegator, string $agent, Principal $p, Cap $cap, int|BigInt $ttl): void
    {
        $agentUid = self::entity('Agent', $agent);
        if (!$this->bundle->store->contains($agentUid)) {
            throw new EngineError('unknown_agent', "agent '$agent' is not registered in entities.json");
        }
        try {
            $ctx = Cedar::fromJson(new JsonObject(['iam' => $this->iamContext($p), 'requested' => new JsonObject([
                'actions' => $cap->actions, 'resources' => $cap->resources, 'ttl' => $ttl, 'budget' => new JsonObject($cap->budget)])]));
        } catch (CedarValueError $e) {
            throw new EngineError('invalid_input', $e->getMessage());
        }
        $v = $this->evaluate($delegator, 'delegate', $agentUid, $ctx, $this->storeFor($p));
        if (!$v['allow']) {
            $why = !$v['policies'] ? 'no policy permits it' : 'forbidden by ' . implode(', ', $v['policies']);
            throw new EngineError('delegation_denied', "$delegator may not delegate to agent '$agent': $why");
        }
    }

    private static function parseCap(JsonObject $i): ?Cap
    {
        if ($i->get('cap') === null) {
            return null;
        }
        $cap = Cap::fromJson($i->get('cap'));
        $cap->validate();
        return $cap;
    }

    private function mint(JsonObject $claims, string $event, int|BigInt $now): JsonObject
    {
        $jti = bin2hex(random_bytes(12));
        $claims->set('jti', $jti);
        $token = $this->keys->sign($claims);
        /** @var JsonObject $cap */
        $cap = $claims->get('cap');
        if (!$cap->get('budget')->isEmpty()) {
            $this->state->section('limits')->set($jti, $cap->get('budget')->copy());
            $this->state->prune($now);
            $this->state->save();
        }
        $user = Tokens::userOf($claims);
        $chain = Tokens::chainOf($claims);
        $this->auditAppend(new JsonObject(['event' => $event, 'token_id' => $jti, 'user' => $user, 'chain' => $chain, 'tenant' => $claims->get('tnt'),
            'task' => $claims->get('task'), 'role' => $claims->get('role'), 'ancestors' => $claims->get('anc'), 'exp' => $claims->get('exp'),
            'cap' => $cap, 'policy_version' => $this->bundle->version]), $now);
        return new JsonObject(['token' => $token, 'token_type' => 'Bearer', 'issued_token_type' => 'urn:ietf:params:oauth:token-type:jwt',
            'token_id' => $jti, 'expires_at' => $claims->get('exp'), 'expires_in' => Num::sub($claims->get('exp'), $now),
            'user' => $user, 'chain' => $chain, 'role' => $claims->get('role'), 'task' => $claims->get('task'), 'cap' => $cap]);
    }

    private function ttl(JsonObject $i): int|BigInt
    {
        return Num::max(1, Num::min(self::int($i, 'ttl', $this->defaultTtl), $this->maxTtl));
    }

    private function issueToken(JsonObject $i): JsonObject
    {
        $now = $this->now($i);
        $idt = self::s($i, 'id_token');
        if ($idt !== null) {
            if ($this->idp === null) {
                throw new EngineError('no_idp', 'no OIDC provider is configured');
            }
            $claims = Tokens::verifyIdToken($idt, $this->idp['jwks'], $this->idp['issuer'], $this->idp['audience'], $now);
            $user = $claims->get($this->idp['user_claim']);
            if (!is_string($user) || $user === '') {
                throw new EngineError('id_token_invalid', "ID token has no '{$this->idp['user_claim']}' claim");
            }
            if (self::s($i, 'user') !== null && $i->get('user') !== $user) {
                throw new EngineError('id_token_invalid', 'the ID token belongs to a different user');
            }
            // Offboarding also covers sign-ins that happened before it: an ID
            // token issued at or before the user's revoke cut-off cannot start
            // a new agent, however long the provider says it lives.
            $cutoff = $this->state->section('revoked_users')->get($user);
            if (Num::isInt($cutoff)) {
                $iat = $claims->get('iat');
                if (!Num::isInt($iat) || Num::cmp($iat, $cutoff) <= 0) {
                    throw new EngineError('id_token_invalid', 'the ID token was issued before this user was revoked; sign in again');
                }
            }
            $groups = null;
            if ($this->idp['groups_claim'] !== null) {
                // the identity provider is the authority on what this human
                // is a member of right now; a missing claim means "of nothing".
                // A dotted name reads a nested claim (Keycloak: realm_access.roles).
                $raw = $claims->get($this->idp['groups_claim']);
                if ($raw === null && str_contains($this->idp['groups_claim'], '.')) {
                    [$raw, $found] = self::lookup($claims, $this->idp['groups_claim']);
                    $raw = $found ? $raw : null;
                }
                try {
                    $groups = $this->groups($raw === null ? [] : $raw, $this->idp['group_type'], $this->idp['group_map']);
                } catch (EngineError) {
                    throw new EngineError('id_token_invalid', "the '{$this->idp['groups_claim']}' claim is not a list of group names");
                }
            }
        } else {
            $user = self::req($i, 'user');
            $groups = $i->get('groups') !== null ? $this->groups($i->get('groups'), 'Group', null) : null;
        }
        $agent = self::req($i, 'agent');
        $cap = self::parseCap($i);
        $role = self::s($i, 'role');
        if ($role === null && $this->requireRole) {
            throw new EngineError('role_required', 'this engine issues tokens only for a named role');
        }
        if ($cap === null && $role === null) {
            throw new EngineError('invalid_cap', "'cap' is required: a root token must state what it may do");
        }
        $ttl = $this->ttl($i);
        $p = new Principal($user, [$agent], self::s($i, 'tenant'), self::s($i, 'task'), null, [], $cap, Num::add($now, $ttl), $role, $groups);
        if ($role !== null) {
            [$cap, $ttl] = $this->applyRole($role, $p, $cap, $ttl);
            $p->cap = $cap;
            $p->exp = Num::add($now, $ttl);
        }
        $this->checkDelegation(self::entity('User', $user), $agent, $p, $cap, $ttl);
        $claims = new JsonObject(['iss' => $this->issuer, 'aud' => Tokens::AUDIENCE, 'sub' => "user:$user", 'iat' => $now, 'exp' => Num::add($now, $ttl),
            'jti' => '', 'act' => Tokens::actFor($p->chain), 'anc' => [], 'cap' => $cap->toJson()]);
        if ($p->tenant !== null) {
            $claims->set('tnt', $p->tenant);
        }
        if ($p->task !== null) {
            $claims->set('task', $p->task);
        }
        if ($role !== null) {
            $claims->set('role', $role);
        }
        if ($groups !== null) {
            $claims->set('grp', $groups);
        }
        return $this->mint($claims, 'token_issued', $now);
    }

    private function exchangeToken(JsonObject $i): JsonObject
    {
        $now = $this->now($i);
        try {
            $parent = $this->verifyToken(self::req($i, 'subject_token'), $now);
        } catch (Deny $d) {
            throw new EngineError($d->reason, $d->detail);
        }
        $pp = Principal::of($parent);
        $actor = self::req($i, 'actor');
        if (Num::cmp(count($pp->chain), $this->maxDepth) >= 0) {
            throw new EngineError('depth_exceeded', 'delegation chains are limited to ' . Num::str($this->maxDepth) . ' agents');
        }
        $cap = self::parseCap($i) ?? $pp->cap;
        $cap->checkNarrowerThan($pp->cap);
        $exp = Num::min(Num::add($now, $this->ttl($i)), $parent->get('exp'));
        if (self::s($i, 'task') !== null && Json::truthy($pp->task) && $i->get('task') !== $pp->task) {
            throw new EngineError('widening', 'a sub-agent token cannot change the task it was issued for');
        }
        if (self::s($i, 'role') !== null && $i->get('role') !== $pp->role) {
            throw new EngineError('widening', 'a sub-agent token cannot change the role it was issued for');
        }
        $this->checkDelegation(self::entity('Agent', $pp->leaf()), $actor, $pp, $cap, Num::sub($exp, $now));
        $chain = [...$pp->chain, $actor];
        $claims = new JsonObject(['iss' => $this->issuer, 'aud' => Tokens::AUDIENCE, 'sub' => $parent->get('sub'), 'iat' => $now, 'exp' => $exp,
            'jti' => '', 'act' => Tokens::actFor($chain), 'anc' => [...$parent->get('anc'), $parent->get('jti')], 'cap' => $cap->toJson()]);
        if (Json::truthy($parent->get('tnt'))) {
            $claims->set('tnt', $parent->get('tnt'));
        }
        $task = Json::truthy($pp->task) ? $pp->task : self::s($i, 'task');
        if (Json::truthy($task)) {
            $claims->set('task', $task);
        }
        if ($pp->role !== null) {
            $claims->set('role', $pp->role);
        }
        if ($pp->groups !== null) {
            $claims->set('grp', $pp->groups);
        }
        // every ancestor's budget travels with the token (see the budget check);
        // the claim is absent, never {}, when no ancestor has a budget
        $lim = $pp->lim !== null ? Json::deepCopy($pp->lim) : new JsonObject();
        if ($pp->cap->budget) {
            $lim->set($parent->get('jti'), new JsonObject($pp->cap->budget));
        }
        if (!$lim->isEmpty()) {
            $claims->set('lim', $lim);
        }
        return $this->mint($claims, 'token_exchanged', $now);
    }

    private function inspectToken(JsonObject $i): JsonObject
    {
        $now = $this->now($i);
        try {
            $c = $this->verifyToken(self::req($i, 'token'), $now);
        } catch (Deny $d) {
            return new JsonObject(['valid' => false, 'reason' => $d->reason, 'detail' => $d->detail]);
        }
        return new JsonObject(['valid' => true, 'claims' => $c, 'chain' => Tokens::chainOf($c), 'user' => Tokens::userOf($c),
            'expires_in' => Num::sub($c->get('exp'), $now)]);
    }

    private function revoke(JsonObject $i): JsonObject
    {
        $now = $this->now($i);
        if ($i->has('user')) {
            // Offboarding, or a human who lost a role: one call ends every
            // token already issued for them, sub-agents included. New tokens
            // are a matter of role membership, not of this list.
            $user = $i->get('user');
            if (!is_string($user) || $user === '') {
                throw new EngineError('invalid_input', "'user' must be a non-empty string");
            }
            // the cut-off only ever moves forward: a clock that steps back (or a
            // second machine with a slower clock) must not revive dead tokens
            $prev = $this->state->section('revoked_users')->get($user);
            $cutoff = Num::isInt($prev) ? Num::max($now, $prev) : $now;
            $this->state->section('revoked_users')->set($user, $cutoff);
            $this->state->save();
            $this->auditAppend(new JsonObject(['event' => 'user_revoked', 'user' => $user, 'issued_up_to' => $cutoff, 'by' => self::s($i, 'by')]), $now);
            return new JsonObject(['revoked_user' => $user, 'issued_up_to' => $cutoff]);
        }
        $t = self::s($i, 'token');
        if ($t !== null) {
            try {
                $c = $this->keys->verify($t, $this->issuer);
            } catch (TokenInvalid $e) {
                throw new EngineError('token_invalid', $e->getMessage());
            }
            $tid = $c->get('jti');
            $exp = $c->get('exp');
        } else {
            $tid = self::req($i, 'token_id');
            $exp = Num::add($now, $this->maxTtl);
        }
        $this->state->section('revoked')->set($tid, $exp);
        $this->state->save();
        $this->auditAppend(new JsonObject(['event' => 'token_revoked', 'token_id' => $tid, 'by' => self::s($i, 'by')]), $now);
        return new JsonObject(['revoked' => $tid]);
    }

    private function approve(JsonObject $i): JsonObject
    {
        $now = $this->now($i);
        $aid = self::req($i, 'approval_id');
        $by = self::req($i, 'by');
        $pending = $this->state->section('pending')->get($aid);
        if ($pending === null) {
            throw new EngineError('unknown_approval', 'no pending request with that approval id');
        }
        if (!$pending instanceof JsonObject) {
            throw new \TypeError('state.json: a pending approval is not an object');
        }
        if ($pending->get('user') === $by) {
            throw new EngineError('self_approval', "the user an agent acts for cannot approve that agent's request");
        }
        // who may approve is itself policy: action "approve" on the agent
        try {
            $ctx = Cedar::fromJson(new JsonObject(['label' => $pending->get('label'), 'for_user' => $pending->get('user'), 'action' => $pending->get('action')]));
        } catch (CedarValueError $e) {
            throw new \TypeError('state.json: ' . $e->getMessage());
        }
        if (!is_string($pending->get('agent'))) {
            throw new \TypeError('state.json: a pending approval names no agent');
        }
        $v = $this->evaluate(self::entity('User', $by), 'approve', self::entity('Agent', $pending->get('agent')), $ctx, $this->bundle->store);
        if (!$v['allow']) {
            throw new EngineError('approval_denied', "no policy lets '$by' approve this request");
        }
        $this->state->section('pending')->remove($aid);
        $exp = Num::add($now, self::int($i, 'ttl', $this->approvalTtl));
        $this->state->section('approvals')->set($aid, new JsonObject(['by' => $by, 'exp' => $exp]));
        $this->state->save();
        $this->auditAppend(new JsonObject(['event' => 'approval_granted', 'approval_id' => $aid, 'by' => $by, 'label' => $pending->get('label'),
            'for_user' => $pending->get('user'), 'agent' => $pending->get('agent'), 'action' => $pending->get('action'),
            'resource' => $pending->get('resource')]), $now);
        return new JsonObject(['approved' => $aid, 'by' => $by, 'expires_at' => $exp]);
    }

    /**
     * Apply the obligations of an earlier decision to data that arrived
     * later. Pure: it authorises nothing by itself.
     */
    private function applyObligations(JsonObject $i): JsonObject
    {
        $ob = $i->get('obligations');
        if (!$ob instanceof JsonObject) {
            throw new EngineError('invalid_input', "'obligations' from a decision is required");
        }
        if (!$i->has('data')) {
            throw new EngineError('invalid_input', "'data' is required");
        }
        $f = $ob->get('fields');
        if (!$f instanceof JsonObject) {
            throw new EngineError('invalid_input', 'obligations.fields is missing; only an allow decision carries a field mask');
        }
        $status = [];
        foreach (['allow' => Fields::ALLOW, 'deny' => Fields::DENY, 'redact' => Fields::REDACT] as $k => $st) {
            $names = $f->get($k);
            foreach (is_array($names) ? $names : [] as $n) {
                if (is_string($n)) {
                    $status[$n] = $st;
                }
            }
        }
        $rf = [];
        foreach (is_array($ob->get('row_filter')) ? $ob->get('row_filter') : [] as $c) {
            if ($c instanceof JsonObject) {
                $rf[] = $c;
            }
        }
        [$data, $masked, $dropped] = Fields::apply($i->get('data'), $status, $rf);
        $did = self::s($i, 'decision_id');
        if ($did !== null) {
            $this->auditAppend(new JsonObject(['event' => 'obligations_applied', 'decision_id' => $did, 'masked' => $masked, 'rows_dropped' => $dropped]),
                $this->now($i));
        }
        return new JsonObject(['data' => $data, 'masked' => $masked, 'rows_dropped' => $dropped]);
    }

    // ---- decisions -----------------------------------------------------------------

    private function evaluateRequest(JsonObject $i, int|BigInt $now, bool $dryRun): Outcome
    {
        $o = new Outcome();
        try {
            $this->steps($o, $i, $now, $dryRun);
        } catch (Deny $d) {
            $o->reason = $d->reason;
            $o->detail = $d->detail;
            $o->trace[] = new JsonObject(['check' => $d->reason, 'result' => 'deny', 'detail' => $d->detail]);
        }
        return $o;
    }

    /** Spend recorded so far for a token in one currency. */
    private function spent(string $tid, string $cur): int|BigInt
    {
        $bucket = $this->state->section('ledger')->get($tid);
        if ($bucket === null) {
            return 0;
        }
        if (!$bucket instanceof JsonObject) {
            throw new \TypeError('state.json: a ledger entry is not an object');
        }
        return Num::of($bucket->get($cur, 0));
    }

    private function steps(Outcome $o, JsonObject $i, int|BigInt $now, bool $dryRun): void
    {
        $passed = static function (string $check, string $msg) use ($o): void {
            $o->trace[] = new JsonObject(['check' => $check, 'result' => 'pass', 'detail' => $msg]);
        };

        $action = self::req($i, 'action');
        $res = $i->get('resource');
        if (!$res instanceof JsonObject) {
            throw new EngineError('invalid_input', "'resource' must be an object with a 'path'");
        }
        $path = self::req($res, 'path');
        $rid = self::s($res, 'id') ?? 'any';
        $callerCtx = $i->get('context');
        if ($callerCtx === null) {
            $callerCtx = new JsonObject();
        }
        if (!$callerCtx instanceof JsonObject) {   // a list, even an empty one, is not an object
            throw new EngineError('invalid_context', "'context' must be an object"
                . ($this->native && $callerCtx === [] ? ' (from PHP, an empty array is an empty list: pass new \\stdClass, or leave the key out)' : ''));
        }
        if ($callerCtx->has('iam')) {
            throw new EngineError('invalid_context', "'iam' is reserved: identity comes from the token, not from the caller");
        }

        // 1. principal
        $token = self::s($i, 'token');
        $chain = $i->get('chain');
        if ($token !== null) {
            try {
                $principal = Principal::of($this->verifyToken($token, $now));
            } catch (Deny $d) {
                if ($d->claims !== null) {
                    $o->principal = Principal::of($d->claims);
                }
                throw $d;
            }
        } elseif ($chain !== null && $this->trustCallerChain && $chain instanceof JsonObject) {
            $agents = [];
            foreach (is_array($chain->get('agents')) ? $chain->get('agents') : [] as $a) {
                if (is_string($a)) {
                    $agents[] = $a;
                }
            }
            if (!$agents) {
                throw new EngineError('invalid_input', 'chain.agents must list at least one agent');
            }
            $principal = new Principal(self::req($chain, 'user'), $agents, self::s($chain, 'tenant'), self::s($chain, 'task'), null, [],
                Cap::unrestricted(), $now, self::s($chain, 'role'),
                $chain->get('groups') !== null ? $this->groups($chain->get('groups'), 'Group', null) : null);
        } elseif ($chain !== null) {
            throw new Deny('token_invalid', 'this engine does not trust caller-supplied chains; send a capability token');
        } else {
            throw new Deny('token_invalid', 'no capability token was presented');
        }
        $o->principal = $principal;
        $passed('token', "user {$principal->user} via " . implode(' -> ', $principal->chain));

        // 2. catalog
        $rdef = $this->bundle->catalog[$path] ?? null;
        if ($rdef === null) {
            throw new Deny('unknown_resource', "'$path' is not in the catalog");
        }

        // 3. tenant
        $attrs = $res->get('attrs');
        if ($attrs === null) {
            $attrs = new JsonObject();
        }
        if (!$attrs instanceof JsonObject) {
            throw new EngineError('invalid_input', 'resource.attrs must be an object');
        }
        $rt = $attrs->get('tenant');
        if (Json::truthy($principal->tenant) && is_string($rt) && $principal->tenant !== $rt) {
            throw new Deny('tenant_mismatch', "token tenant '{$principal->tenant}' cannot touch a resource of tenant '$rt'");
        }

        // 4. capability
        $cap = $principal->cap;
        if (!$cap->allowsAction($action)) {
            throw new Deny('capability_action', "the token does not carry action '$action'");
        }
        if (!$cap->allowsResource($path, $rid)) {
            throw new Deny('capability_resource', "the token does not cover $path/$rid");
        }
        $passed('capability', 'token covers the action and the resource');

        // 5. policy
        $etype = $rdef['entity_type'];
        $rUid = self::entity($etype, $rid);
        if (is_array($i->get('fields'))) {
            $fieldNames = [];
            foreach ($i->get('fields') as $f) {
                if (!is_string($f) || !array_key_exists($f, $rdef['fields'])) {
                    throw new Deny('unknown_field', "'$path." . (is_string($f) ? $f : Json::compact($f, false)) . "' is not in the catalog");
                }
                $fieldNames[] = $f;
            }
        } else {
            $fieldNames = array_map('strval', array_keys($rdef['fields']));
            sort($fieldNames, SORT_STRING);
        }
        $extra = [];
        if (!$this->bundle->store->contains($rUid)) {
            $extra[] = new JsonObject(['uid' => new JsonObject(['type' => $etype, 'id' => $rid]), 'attrs' => $attrs, 'parents' => []]);
        } elseif (!$attrs->isEmpty()) {
            throw new EngineError('invalid_input', "$rUid is defined in entities.json; do not send attrs for it");
        }
        foreach ($fieldNames as $n) {
            $fid = "$path.$n";
            $extra[] = new JsonObject([
                'uid' => new JsonObject(['type' => 'Field', 'id' => $fid]),
                'attrs' => new JsonObject(['path' => $fid, 'name' => $n, 'resource' => $path, 'labels' => $rdef['fields'][$n]['labels'],
                    'of' => new JsonObject(['__entity' => new JsonObject(['type' => $etype, 'id' => $rid])])]),
                'parents' => [new JsonObject(['type' => $etype, 'id' => $rid])],
            ]);
        }
        try {
            $store = $this->storeFor($principal)->overlay($extra);
        } catch (CedarValueError $e) {
            throw new EngineError('invalid_input', 'resource entity: ' . $e->getMessage());
        }
        $fullCtx = $callerCtx->copy();
        $fullCtx->set('iam', $this->iamContext($principal));
        try {
            $ctx = Cedar::fromJson($fullCtx);
        } catch (CedarValueError $e) {
            throw new EngineError('invalid_context', $e->getMessage() . ' (use integers, strings, booleans, lists and objects; no floats or nulls)');
        }
        $pUid = self::entity('Agent', $principal->leaf());
        $v = $this->evaluate($pUid, $action, $rUid, $ctx, $store);
        array_push($o->errors, ...$v['errors']);
        $o->policies = $v['policies'];
        if (!$v['allow']) {
            if ($v['forbid_error']) {
                throw new Deny('policy_error', 'a forbid policy failed to evaluate, so the request is denied');
            }
            if (!$v['policies']) {
                throw new Deny('no_matching_permit', 'no policy permits this request');
            }
            throw new Deny('policy_forbid', 'forbidden by ' . implode(', ', $v['policies']));
        }
        $passed('policy', 'permitted by ' . implode(', ', $v['policies']));

        // 6. obligations carried by the permits that decided
        $approvalLabel = null;
        foreach ($v['policies'] as $pid) {
            $ann = $this->bundle->policies[$pid]->annotations;
            if (array_key_exists('row_filter', $ann)) {
                try {
                    array_push($o->rowFilter, ...self::parseRowFilter($ann['row_filter'], $fullCtx));
                } catch (Deny $d) {
                    throw new Deny($d->reason, "$pid: " . $d->detail);
                }
            }
            if (array_key_exists('rate_limit', $ann)) {
                $rate = self::parseRate($ann['rate_limit']);
                if ($rate === null) {
                    throw new Deny('policy_error', "$pid: rate_limit must be \"<count>/<seconds>\"");
                }
                $o->rate[] = ["$pid|{$principal->leaf()}|{$principal->user}", $rate[0], $rate[1]];
            }
            if (array_key_exists('require_approval', $ann)) {
                $approvalLabel = $ann['require_approval'];
            }
        }
        foreach ($o->rate as [$key, $n, $w]) {
            $q = $this->rate[$key] ?? [];
            $edge = Num::sub($now, $w);
            while ($q && Num::cmp($q[0], $edge) <= 0) {
                array_shift($q);
            }
            $this->rate[$key] = $q;
            $o->rateLimit = new JsonObject(['limit' => $n, 'window_seconds' => $w, 'used' => count($q)]);
            if (Num::cmp(count($q), $n) >= 0) {
                throw new Deny('rate_limited', 'more than ' . Num::str($n) . ' calls in ' . Num::str($w) . ' seconds');
            }
        }

        // 7. budget
        if ($callerCtx->has('spend')) {
            $sp = $callerCtx->get('spend');
            $cur = $sp instanceof JsonObject ? $sp->get('currency') : null;
            $amount = $sp instanceof JsonObject ? $sp->get('amount') : null;
            if (!is_string($cur) || !Num::isInt($amount) || Num::cmp($amount, 0) < 0) {
                throw new EngineError('invalid_context', 'context.spend must be {currency: string, amount: non-negative integer in minor units}');
            }
            if ($principal->jti === null) {
                throw new Deny('budget_exceeded', 'spending needs a capability token with a budget');
            }
            if (!array_key_exists($cur, $cap->budget)) {
                throw new Deny('budget_exceeded', "the token carries no $cur budget");
            }
            $own = $cap->budget[$cur];
            $mine = $this->spent($principal->jti, $cur);
            if (Num::cmp(Num::add($mine, $amount), $own) > 0) {
                throw new Deny('budget_exceeded', Num::str($amount) . " $cur would exceed this token's budget of " . Num::str($own)
                    . ' (already spent ' . Num::str($mine) . ')');
            }
            $limits = $this->state->section('limits');
            foreach ($principal->anc as $a) {
                $entry = $limits->get($a);
                if ($entry !== null && !$entry instanceof JsonObject) {
                    throw new \TypeError('state.json: a limits entry is not an object');
                }
                // An ancestor's budget is in this engine's state when it issued the
                // ancestor, and in the token's `lim` claim always: a verify-only
                // engine elsewhere must enforce it too.
                $limit = $entry?->get($cur);
                if ($limit === null) {
                    $fromToken = $principal->lim?->get($a);
                    $limit = $fromToken instanceof JsonObject ? $fromToken->get($cur) : null;
                }
                if ($limit !== null && Num::cmp(Num::add($this->spent($a, $cur), $amount), Num::of($limit)) > 0) {
                    throw new Deny('budget_exceeded', Num::str($amount) . " $cur would exceed the budget of ancestor token $a");
                }
            }
            $o->spend = [$cur, $amount];
            $passed('budget', 'within the budget of every token in the chain');
        }

        // 8. human approval
        if ($approvalLabel !== null) {
            // bound to the exact request, resource attributes included ($attrs is the
            // object as sent, or {} - an empty object, not [] - when absent or null)
            $aid = substr(Canon::hashValue(new JsonObject(['user' => $principal->user, 'chain' => $principal->chain, 'tenant' => $principal->tenant,
                'action' => $action, 'resource' => "$path/$rid", 'attrs' => $attrs, 'context' => $callerCtx, 'label' => $approvalLabel])), 0, 24);
            $grant = $this->state->section('approvals')->get($aid);
            if ($grant instanceof JsonObject && !$grant->isEmpty() && Num::cmp(Num::of($grant->get('exp')), $now) > 0) {
                $o->approved = [$aid, $grant->get('by')];
                $passed('approval', 'approved by ' . (is_string($grant->get('by')) ? $grant->get('by') : Json::compact($grant->get('by'), false)));
            } else {
                if (!$dryRun) {
                    $this->state->section('pending')->set($aid, new JsonObject(['label' => $approvalLabel, 'user' => $principal->user,
                        'agent' => $principal->leaf(), 'action' => $action, 'resource' => "$path/$rid", 'requested_at' => $now]));
                    $this->state->save();
                }
                $o->approval = new JsonObject(['id' => $aid, 'label' => $approvalLabel]);
                throw new Deny('approval_required', 'a human must approve this (' . (is_string($approvalLabel) ? $approvalLabel : Json::compact($approvalLabel, false)) . ')');
            }
        }

        // 9. fields
        $status = [];
        $fieldTrace = [];
        foreach ($fieldNames as $n) {
            $fid = "$path.$n";
            $fdef = $rdef['fields'][$n];
            $byLabel = false;
            foreach ($fdef['labels'] as $l) {
                $byLabel = $byLabel || (is_string($l) && in_array($l, $cap->denyLabels, true));
            }
            if (in_array($fid, $cap->denyFields, true) || $byLabel) {
                $allowed = false;
                $by = 'capability';
            } else {
                $fv = $this->evaluate($pUid, $action, new Entity('Field', $fid), $ctx, $store);
                array_push($o->errors, ...$fv['errors']);
                $allowed = $fv['allow'];
                $by = $fv['policies'] ?: 'no_matching_permit';
            }
            if ($allowed) {
                $o->fieldAllow[] = $n;
                $status[$n] = Fields::ALLOW;
            } else {
                $o->fieldDeny[] = $n;
                if ($fdef['mask'] === 'redact') {
                    $o->fieldRedact[] = $n;
                    $status[$n] = Fields::REDACT;
                } else {
                    $status[$n] = Fields::DENY;
                }
            }
            $fieldTrace[] = new JsonObject(['field' => $n, 'effect' => $allowed ? 'allow' : 'deny', 'by' => $by]);
        }
        $o->trace[] = new JsonObject(['check' => 'fields', 'result' => 'pass', 'fields' => $fieldTrace]);
        $o->mask = $status;
        $o->allow = true;
        $o->reason = 'policy_permit';
    }

    private function decide(JsonObject $i, bool $withData): JsonObject
    {
        $now = $this->now($i);
        $dryRun = $i->get('dry_run') === true;
        $strict = $i->get('strict') === true;
        if ($withData && !$i->has('data')) {
            throw new EngineError('invalid_input', "'data' is required for filter");
        }
        $data = $withData ? $i->get('data') : null;
        $o = $this->evaluateRequest($i, $now, $dryRun);

        // 10. strict mode: for tool *inputs*, where silently dropping a field
        // would change what the agent asked for
        if ($o->allow && $strict && $withData) {
            $denied = Fields::apply($data, $o->mask, [])[1];
            if ($denied) {
                $o->allow = false;
                $o->reason = 'field_denied';
                $o->detail = 'the input contains fields this principal may not use: ' . implode(', ', $denied);
                $o->trace[] = new JsonObject(['check' => 'field_denied', 'result' => 'deny', 'detail' => $o->detail]);
            }
        }

        // commit the side effects of an allowed call
        if ($o->allow && !$dryRun) {
            foreach ($o->rate as [$key]) {
                $this->rate[$key][] = $now;
            }
            $dirty = false;
            if ($o->spend !== null && $o->principal !== null) {
                [$cur, $amount] = $o->spend;
                $ledger = $this->state->section('ledger');
                foreach ([...$o->principal->anc, $o->principal->jti] as $tid) {
                    $bucket = $ledger->get($tid);
                    if ($bucket === null) {
                        $bucket = new JsonObject();
                        $ledger->set($tid, $bucket);
                    }
                    if (!$bucket instanceof JsonObject) {
                        throw new \TypeError('state.json: a ledger entry is not an object');
                    }
                    $bucket->set($cur, Num::add(Num::of($bucket->get($cur, 0)), $amount));
                }
                $dirty = true;
            }
            if ($o->approved !== null) {
                // an approval is good for one call
                $this->state->section('approvals')->remove($o->approved[0]);
                $dirty = true;
            }
            if ($dirty) {
                $this->state->save();
            }
        }

        $wouldDeny = !$o->allow;
        $shadowed = $this->shadow && $wouldDeny;
        $out = new JsonObject(['effect' => ($o->allow || $shadowed) ? 'allow' : 'deny', 'reason' => $shadowed ? 'shadow_allow' : $o->reason]);
        $out->set('rule', EngineError::ruleId($out->get('reason')));
        if ($o->detail !== '' && !$shadowed) {
            $out->set('detail', $o->detail);
        }
        $out->set('policies', $o->policies);
        $out->set('policy_version', $this->bundle->version);
        $out->set('principal', $o->principal?->toJson());
        if ($this->shadow) {
            $out->set('shadow', true);
            if ($wouldDeny) {
                $out->set('would_deny', new JsonObject(['reason' => $o->reason, 'detail' => $o->detail]));
            }
        }
        if ($o->approval !== null) {
            $out->set('approval', $o->approval);
        }

        $obligations = new JsonObject();
        $masked = [];
        $rowsDropped = 0;
        if ($o->allow) {
            $obligations->set('fields', new JsonObject(['allow' => $o->fieldAllow, 'deny' => $o->fieldDeny, 'redact' => $o->fieldRedact]));
            if ($o->rowFilter) {
                $obligations->set('row_filter', $o->rowFilter);
            }
            if ($o->rateLimit !== null) {
                $obligations->set('rate_limit', $o->rateLimit);
            }
            if ($o->approved !== null) {
                $obligations->set('approved', new JsonObject(['id' => $o->approved[0], 'by' => $o->approved[1]]));
            }
        }
        if ($withData) {
            if ($o->allow) {
                [$filtered, $masked, $rowsDropped] = Fields::apply($data, $o->mask, $o->rowFilter);
                if ($this->shadow) {
                    // shadow mode never changes data; it reports what it would do
                    $out->set('data', $data);
                    $out->set('would_mask', $masked);
                    $out->set('would_drop_rows', $rowsDropped);
                } else {
                    $out->set('data', $filtered);
                    $out->set('masked', $masked);
                    $out->set('rows_dropped', $rowsDropped);
                }
            } else {
                $out->set('data', $shadowed ? $data : null);
            }
        }
        $out->set('obligations', $obligations);
        if ($o->errors) {
            $out->set('policy_errors', $o->errors);
        }
        if ($i->get('explain') === true) {
            $out->set('explain', $o->trace);
        }

        $this->counter++;
        $p = $o->principal;
        $requestHash = Canon::hashValue(new JsonObject(['action' => $i->get('action'), 'resource' => $i->get('resource'),
            'context' => $i->get('context'), 'token_id' => $p?->jti]));
        $decisionId = 'd-' . substr(hash('sha256', $requestHash . Num::str($now) . $this->counter . getmypid()), 0, 16);
        $out->set('decision_id', $decisionId);

        if (!$dryRun) {
            $res = $i->get('resource');
            $this->auditAppend(new JsonObject([
                'event' => 'decision', 'decision_id' => $decisionId, 'op' => $withData ? 'filter' : 'authorize',
                'effect' => $o->allow ? 'allow' : 'deny', 'reason' => $o->reason, 'detail' => $o->detail,
                'enforced' => !$this->shadow, 'policies' => $o->policies, 'policy_version' => $this->bundle->version,
                'user' => $p?->user, 'chain' => $p?->chain, 'role' => $p?->role, 'tenant' => $p?->tenant,
                'task' => $p?->task, 'token_id' => $p?->jti, 'token_exp' => $p?->exp,
                'action' => $i->get('action'),
                'resource' => (self::s($res, 'path') ?? '?') . '/' . (self::s($res, 'id') ?? 'any'),
                'obligations' => $obligations, 'masked' => $masked, 'rows_dropped' => $rowsDropped, 'approval' => $o->approval,
                'spend' => $o->spend !== null ? new JsonObject(['currency' => $o->spend[0], 'amount' => $o->spend[1]]) : null,
                'request_hash' => $requestHash,
            ]), $now);
        }
        return $out;
    }
}
