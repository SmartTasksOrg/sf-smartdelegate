<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * Policy bundle: compiled policies, entity store, field catalog, signature.
 *
 *     bundle/
 *       policies.json     Cedar's JSON policy form, keyed by policy id. This
 *                         is what the engine evaluates.
 *       policies/*.cedar  the human-written source policies.json is compiled
 *                         from (`smartdelegate bundle compile`, Rust port)
 *       entities.json     users, groups, agents
 *       catalog.json      resources, fields, classification labels
 *       roles.json        roles a human can act in (optional)
 *       tests/*.json      policy unit tests (not part of the version)
 *       bundle.sig.json   file hashes + Ed25519 signature
 *
 * Keys: a private key is base64 of the Ed25519 PKCS#8 version 1 DER (48
 * bytes: a fixed 16-byte prefix, then the seed); a public key is base64 of
 * the 32 raw bytes; the key id is the first 16 hex characters of
 * sha256(public key).
 */
final class Bundle
{
    private const PKCS8_PREFIX = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20";

    public readonly string $dir;
    public readonly string $version;
    public readonly ?string $signedBy;
    /** @var array<array-key,Policy> policy id => Policy */
    public array $policies = [];
    public Store $store;
    /** @var array<array-key,JsonObject> "Type::id" => attrs exactly as written in entities.json */
    public array $attrs = [];
    /** @var array<array-key,array{entity_type:string,fields:array<array-key,array{labels:list<mixed>,mask:?string}>}> */
    public array $catalog = [];
    /** @var array<array-key,Role> */
    public array $roles = [];

    private static function read(string $path): string
    {
        $text = is_file($path) || is_link($path) ? @file_get_contents($path) : false;
        if ($text === false) {
            $err = error_get_last()['message'] ?? 'cannot read the file';
            throw new EngineError('bundle_io', "$path: " . (is_dir($path) ? 'is a directory' : (file_exists($path) ? $err : 'No such file or directory')));
        }
        if (!mb_check_encoding($text, 'UTF-8')) {
            throw new EngineError('bundle_io', "$path: not UTF-8 text");
        }
        return $text;
    }

    private static function digest(string $path): string
    {
        return hash('sha256', str_replace("\r\n", "\n", self::read($path)));
    }

    /**
     * Relative path -> sha256 for every file that defines behaviour. Line
     * endings are normalised so a Windows checkout has the same version.
     */
    public static function manifest(string $dir): JsonObject
    {
        $files = [];
        if (!file_exists("$dir/policies.json")) {
            throw new EngineError('bundle_io', "$dir/policies.json: missing. This port loads compiled policies; run `smartdelegate bundle compile` (Rust port) on the .cedar sources");
        }
        $files['policies.json'] = self::digest("$dir/policies.json");
        foreach (['entities.json', 'catalog.json', 'roles.json'] as $name) {
            if (file_exists("$dir/$name")) {
                $files[$name] = self::digest("$dir/$name");
            }
        }
        return new JsonObject($files);
    }

    public static function versionOf(JsonObject $files): string
    {
        return hash('sha256', Canon::canon($files));
    }

    // ---- keys ------------------------------------------------------------------

    /** @return array{string,string} private key (base64 PKCS#8), public key (base64 raw) */
    public static function keygen(): array
    {
        $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $pair = sodium_crypto_sign_seed_keypair($seed);
        $out = [base64_encode(self::PKCS8_PREFIX . $seed), base64_encode(sodium_crypto_sign_publickey($pair))];
        sodium_memzero($seed);
        sodium_memzero($pair);
        return $out;
    }

    /** @return array{string,string} sodium secret key (64 bytes), raw public key (32 bytes) */
    public static function loadPrivate(string $b64): array
    {
        $der = Tokens::b64Strict(Json::pyStrip($b64));
        if ($der === null || strlen($der) !== 48 || strncmp($der, self::PKCS8_PREFIX, 16) !== 0) {
            throw new EngineError('crypto', 'private key is not base64 Ed25519 PKCS#8');
        }
        $pair = sodium_crypto_sign_seed_keypair(substr($der, 16));
        return [sodium_crypto_sign_secretkey($pair), sodium_crypto_sign_publickey($pair)];
    }

    /** @return string the 32 raw bytes */
    public static function loadPublic(mixed $b64): string
    {
        $raw = is_string($b64) ? Tokens::b64Strict(Json::pyStrip($b64)) : null;
        if ($raw === null || strlen($raw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new EngineError('crypto', 'public key is not base64 of 32 raw Ed25519 bytes');
        }
        return $raw;
    }

    public static function keyId(string $publicB64): string
    {
        return substr(hash('sha256', self::loadPublic($publicB64)), 0, 16);
    }

    /** Sign the bundle in `dir`: writes bundle.sig.json and returns its content. */
    public static function sign(string $dir, string $privateB64): JsonObject
    {
        [$secret, $public] = self::loadPrivate($privateB64);
        $files = self::manifest($dir);
        $version = self::versionOf($files);
        $payload = new JsonObject(['files' => $files, 'version' => $version]);
        $out = new JsonObject(['files' => $files, 'version' => $version, 'key_id' => substr(hash('sha256', $public), 0, 16), 'alg' => 'Ed25519',
            'signature' => base64_encode(sodium_crypto_sign_detached(Canon::canon($payload), $secret))]);
        sodium_memzero($secret);
        if (@file_put_contents("$dir/bundle.sig.json", Json::encode($out, true, false, ',', ': ', 2)) === false) {
            throw new EngineError('bundle_io', "$dir/bundle.sig.json: cannot write");
        }
        return $out;
    }

    private static function verifySignature(string $dir, JsonObject $files, string $publicB64): void
    {
        $p = "$dir/bundle.sig.json";
        if (!file_exists($p)) {
            throw new EngineError('bundle_unsigned', 'a signed bundle is required, but bundle.sig.json is missing');
        }
        $text = self::read($p);
        try {
            $sig = Json::decode($text);
            $rawSig = $sig instanceof JsonObject ? Tokens::b64Strict($sig->get('signature', '')) : null;
        } catch (JsonError) {
            $rawSig = null;
        }
        if ($rawSig === null) {
            throw new EngineError('bundle_signature', 'bundle.sig.json is malformed');
        }
        $payload = new JsonObject(['files' => $sig->get('files'), 'version' => $sig->get('version')]);
        $public = self::loadPublic($publicB64);
        try {
            $ok = strlen($rawSig) === SODIUM_CRYPTO_SIGN_BYTES && sodium_crypto_sign_verify_detached($rawSig, Canon::canon($payload), $public);
        } catch (\SodiumException) {
            $ok = false;
        }
        if (!$ok) {
            throw new EngineError('bundle_signature', 'bundle signature does not verify with the configured key');
        }
        if (!Json::pyEq($files, $sig->get('files'))) {
            throw new EngineError('bundle_signature', 'bundle files changed after signing');
        }
    }

    /** What Python's `for x in v` yields for a JSON value, for the places where the reference does not check the type. */
    private static function pyIter(mixed $v): array
    {
        if (is_array($v)) {
            return $v;
        }
        if ($v instanceof JsonObject) {
            return $v->keys();
        }
        if (is_string($v)) {
            return mb_str_split($v, 1, 'UTF-8');
        }
        throw new CedarValueError(get_debug_type($v) . ' is not a list');
    }

    /**
     * @param string|null $publicKey when set, the bundle must carry a valid
     *                               signature by that key or loading fails
     */
    public function __construct(string $dir, ?string $publicKey = null)
    {
        $this->dir = $dir;
        $files = self::manifest($dir);
        $this->version = self::versionOf($files);
        $signedBy = null;
        if ($publicKey !== null && $publicKey !== '') {
            self::verifySignature($dir, $files, $publicKey);
            $signedBy = self::keyId($publicKey);
        }
        $this->signedBy = $signedBy;

        $text = self::read("$dir/policies.json");
        try {
            $doc = Json::decode($text);
        } catch (JsonError $e) {
            throw new EngineError('policy_parse', 'policies.json: ' . $e->getMessage());
        }
        $compiled = $doc instanceof JsonObject ? $doc->get('policies') : null;
        if (!$compiled instanceof JsonObject) {
            throw new EngineError('policy_parse', 'policies.json: expected {"policies": {...}}');
        }
        // policies.json records the hash of each .cedar file it was compiled
        // from. This port cannot parse Cedar text, but it can tell when a
        // source was edited (or added) without recompiling, so the policy a
        // reviewer reads is the policy that runs.
        $sources = $doc->get('sources') instanceof JsonObject ? $doc->get('sources') : new JsonObject();
        $onDisk = [];
        if (is_dir("$dir/policies")) {
            $names = [];
            foreach (scandir("$dir/policies") ?: [] as $name) {
                if ($name !== '.' && $name !== '..' && str_ends_with($name, '.cedar')) {
                    $names[] = $name;
                }
            }
            sort($names, SORT_STRING);
            foreach ($names as $name) {
                $onDisk["policies/$name"] = self::digest("$dir/policies/$name");
            }
        }
        if ($onDisk && !Json::pyEq(new JsonObject($onDisk), $sources)) {
            $changed = [];
            foreach (array_unique([...array_map('strval', array_keys($onDisk)), ...$sources->keys()]) as $k) {
                if (!Json::pyEq($onDisk[$k] ?? null, $sources->get($k))) {
                    $changed[] = $k;
                }
            }
            sort($changed, SORT_STRING);
            throw new EngineError('bundle_stale', 'policies.json does not match the .cedar sources (' . implode(', ', $changed)
                . '); run `smartdelegate bundle compile` from the Rust port');
        }
        foreach ($compiled->m as $pid => $est) {
            try {
                $this->policies[$pid] = new Policy((string) $pid, $est);
            } catch (Unsupported $e) {
                throw new EngineError('policy_parse', "policies.json: $pid: " . $e->getMessage());
            }
        }

        $this->store = new Store();
        if (file_exists("$dir/entities.json")) {
            $text = self::read("$dir/entities.json");
            try {
                $entities = Json::decode($text);
                $ok = is_array($entities);
                foreach ($ok ? $entities : [] as $e) {
                    $ok = $ok && $e instanceof JsonObject;
                }
                if (!$ok) {
                    throw new CedarValueError('expected a list of entities');
                }
                $this->store = new Store($entities);
                foreach ($entities as $e) {
                    $uid = Store::uid($e->get('uid'));
                    $attrs = $e->get('attrs');
                    $this->attrs["{$uid->type}::{$uid->id}"] = Json::truthy($attrs) ? $attrs : new JsonObject();
                }
            } catch (JsonError|CedarValueError $e) {
                throw new EngineError('entities_parse', 'entities.json: ' . $e->getMessage());
            }
        }

        if (file_exists("$dir/catalog.json")) {
            $text = self::read("$dir/catalog.json");
            try {
                $cat = Json::decode($text);
                if (!$cat instanceof JsonObject) {
                    throw new CedarValueError('catalog.json must be an object');
                }
                $resources = Json::truthy($cat->get('resources')) ? $cat->get('resources') : new JsonObject();
                if (!$resources instanceof JsonObject) {
                    throw new CedarValueError('resources must be an object');
                }
                foreach ($resources->m as $path => $rdef) {
                    if (!$rdef instanceof JsonObject) {
                        throw new CedarValueError("$path: must be an object");
                    }
                    if (!Cedar::validType($rdef->get('entity_type'))) {
                        throw new CedarValueError("$path: entity_type is missing or malformed");
                    }
                    $fdefs = Json::truthy($rdef->get('fields')) ? $rdef->get('fields') : new JsonObject();
                    if (!$fdefs instanceof JsonObject) {
                        throw new CedarValueError("$path: fields must be an object");
                    }
                    $fields = [];
                    foreach ($fdefs->m as $name => $fdef) {
                        if (!$fdef instanceof JsonObject) {
                            throw new CedarValueError("$path.$name: must be an object");
                        }
                        $mask = $fdef->get('mask');
                        if ($mask !== null && $mask !== 'drop' && $mask !== 'redact') {
                            throw new CedarValueError("$path.$name: mask must be 'drop' or 'redact'");
                        }
                        $labels = $fdef->get('labels');
                        $fields[$name] = ['labels' => Json::truthy($labels) ? self::pyIter($labels) : [], 'mask' => $mask];
                    }
                    $this->catalog[$path] = ['entity_type' => $rdef->get('entity_type'), 'fields' => $fields];
                }
            } catch (JsonError|CedarValueError $e) {
                throw new EngineError('catalog_parse', $e->getMessage());
            }
        }

        if (file_exists("$dir/roles.json")) {
            try {
                $doc = Json::decode(self::read("$dir/roles.json"));
                if (!$doc instanceof JsonObject || !$doc->get('roles') instanceof JsonObject) {
                    throw new CedarValueError('expected {"roles": {...}}');
                }
                foreach ($doc->get('roles')->m as $name => $rdef) {
                    $this->roles[$name] = new Role((string) $name, $rdef);
                }
            } catch (EngineError $e) {
                throw new EngineError('roles_parse', 'roles.json: ' . $e->detail);
            } catch (JsonError|CedarValueError $e) {
                throw new EngineError('roles_parse', 'roles.json: ' . $e->getMessage());
            }
        }
    }
}
