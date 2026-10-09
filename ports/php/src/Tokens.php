<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * Capability tokens: EdDSA-signed JWTs with an RFC 8693 `act` delegation
 * chain and a `cap` claim that can only be narrowed on each hop. Also the
 * verification of OIDC ID tokens against a static JWKS.
 *
 * Ed25519 comes from ext-sodium; RSA and ECDSA (ID tokens only) from
 * ext-openssl.
 */
final class Tokens
{
    public const AUDIENCE = 'smartdelegate';

    public static function b64u(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * base64url, strict: only A-Z a-z 0-9 - _, no padding, nothing skipped.
     * One token has one spelling.
     *
     * @throws \UnexpectedValueException
     */
    public static function b64uDec(mixed $text): string
    {
        if (!is_string($text) || preg_match('/^[A-Za-z0-9_-]+$/D', $text) !== 1 || strlen($text) % 4 === 1) {
            throw new \UnexpectedValueException('not base64url');
        }
        $out = base64_decode(strtr($text, '-_', '+/') . str_repeat('=', (4 - strlen($text) % 4) % 4), true);
        if ($out === false) {
            throw new \UnexpectedValueException('not base64url');
        }
        return $out;
    }

    /** base64 with padding, strict (Python's b64decode(validate=True)). Null when it is not. */
    public static function b64Strict(mixed $text): ?string
    {
        if (!is_string($text) || strlen($text) % 4 !== 0 || preg_match('/^[A-Za-z0-9+\/]*={0,2}$/D', $text) !== 1) {
            return null;
        }
        $out = base64_decode($text, true);
        return $out === false ? null : $out;
    }

    // ---- claims ----------------------------------------------------------------

    /** RFC 8693 actor chain: the current actor is outermost. */
    public static function actFor(array $chain): ?JsonObject
    {
        $act = null;
        foreach ($chain as $agent) {
            $act = $act === null ? new JsonObject(['sub' => "agent:$agent"]) : new JsonObject(['sub' => "agent:$agent", 'act' => $act]);
        }
        return $act;
    }

    /** Agents root-first: ["support-bot", "refund-helper"]. @return list<string> */
    public static function chainOf(JsonObject $claims): array
    {
        $out = [];
        $cur = $claims->get('act');
        while ($cur instanceof JsonObject && is_string($cur->get('sub'))) {
            $sub = $cur->get('sub');
            $out[] = str_starts_with($sub, 'agent:') ? substr($sub, 6) : $sub;
            $cur = $cur->get('act');
        }
        return array_reverse($out);
    }

    public static function userOf(JsonObject $claims): string
    {
        $sub = $claims->get('sub', '');
        return str_starts_with($sub, 'user:') ? substr($sub, 5) : $sub;
    }

    // ---- OIDC ID tokens --------------------------------------------------------

    private static function derLen(int $n): string
    {
        if ($n < 0x80) {
            return chr($n);
        }
        $b = ltrim(pack('N', $n), "\0");
        return chr(0x80 | strlen($b)) . $b;
    }

    private static function der(int $tag, string $body): string
    {
        return chr($tag) . self::derLen(strlen($body)) . $body;
    }

    /** Unsigned big-endian bytes -> DER INTEGER. */
    private static function derInt(string $bytes): string
    {
        $bytes = ltrim($bytes, "\0");
        if ($bytes === '' || (ord($bytes[0]) & 0x80)) {
            $bytes = "\0" . $bytes;
        }
        return self::der(0x02, $bytes);
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function jwkPart(JsonObject $jwk, string $name): string
    {
        if (!$jwk->has($name)) {
            throw new \UnexpectedValueException("'$name'");
        }
        return self::b64uDec($jwk->get($name));
    }

    /** @return bool true when the signature verifies; throws for an unusable key or algorithm */
    private static function verifyJws(mixed $alg, JsonObject $jwk, string $signingInput, string $sig): bool
    {
        $kty = $jwk->get('kty');
        if (in_array($alg, ['RS256', 'RS384', 'RS512'], true) && $kty === 'RSA') {
            $e = ltrim(self::jwkPart($jwk, 'e'), "\0");
            $n = ltrim(self::jwkPart($jwk, 'n'), "\0");
            if ($n === '' || $e === '' || (ord($e[strlen($e) - 1]) & 1) === 0 || (strlen($e) === 1 && ord($e) < 3)
                || strlen($e) > strlen($n) || (strlen($e) === strlen($n) && strcmp($e, $n) >= 0)) {
                throw new \UnexpectedValueException('malformed RSA public key');
            }
            $rsa = self::der(0x30, self::derInt($n) . self::derInt($e));
            $spki = self::der(0x30, hex2bin('300d06092a864886f70d0101010500') . self::der(0x03, "\0" . $rsa));
            return self::opensslVerify($spki, $signingInput, $sig, 'sha' . substr($alg, 2));
        }
        if (($alg === 'ES256' || $alg === 'ES384') && $kty === 'EC') {
            [$size, $prefix] = $alg === 'ES256'
                ? [32, '3059301306072a8648ce3d020106082a8648ce3d03010703420004']
                : [48, '3076301006072a8648ce3d020106052b8104002203620004'];
            if (strlen($sig) !== 2 * $size) {
                return false;
            }
            $x = ltrim(self::jwkPart($jwk, 'x'), "\0");
            $y = ltrim(self::jwkPart($jwk, 'y'), "\0");
            if (strlen($x) > $size || strlen($y) > $size) {
                throw new \UnexpectedValueException('malformed EC public key');
            }
            $point = str_pad($x, $size, "\0", STR_PAD_LEFT) . str_pad($y, $size, "\0", STR_PAD_LEFT);
            // a JWS ECDSA signature is r || s; OpenSSL wants DER SEQUENCE { r, s }
            $der = self::der(0x30, self::derInt(substr($sig, 0, $size)) . self::derInt(substr($sig, $size)));
            return self::opensslVerify(hex2bin($prefix) . $point, $signingInput, $der, 'sha' . substr($alg, 2));
        }
        if ($alg === 'EdDSA' && $kty === 'OKP' && $jwk->get('crv') === 'Ed25519') {
            $pub = self::jwkPart($jwk, 'x');
            if (strlen($pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new \UnexpectedValueException('malformed Ed25519 public key');
            }
            return strlen($sig) === SODIUM_CRYPTO_SIGN_BYTES && sodium_crypto_sign_verify_detached($sig, $signingInput, $pub);
        }
        throw new \UnexpectedValueException('unsupported signing algorithm');
    }

    private static function opensslVerify(string $spkiDer, string $data, string $sig, string $hash): bool
    {
        $key = openssl_pkey_get_public(self::pem($spkiDer));
        if ($key === false) {
            while (openssl_error_string() !== false) {
            }
            throw new \UnexpectedValueException('key or signature is malformed');
        }
        $r = openssl_verify($data, $sig, $key, $hash);
        while (openssl_error_string() !== false) {
        }
        return $r === 1;
    }

    /**
     * Verify an OIDC ID token against a static JWKS and return its claims.
     *
     * @throws EngineError id_token_invalid
     */
    public static function verifyIdToken(string $idToken, mixed $jwks, string $issuer, string $audience, int|BigInt $now): JsonObject
    {
        $bad = static fn (string $msg): EngineError => new EngineError('id_token_invalid', $msg);
        try {
            $parts = explode('.', $idToken);
            if (count($parts) !== 3) {
                throw new \UnexpectedValueException('not three parts');
            }
            [$headB, $bodyB, $sigB] = $parts;
            $header = Json::decodeBytes(self::b64uDec($headB));
            $sig = self::b64uDec($sigB);
            if (!$header instanceof JsonObject || !$header->has('alg')) {
                throw new \UnexpectedValueException('no alg');
            }
            $alg = $header->get('alg');
        } catch (\Throwable) {
            throw $bad('not a JWT');
        }
        if (!$jwks instanceof JsonObject) {
            throw new \RuntimeException('the configured JWKS is not an object');
        }
        $keys = [];
        $list = $jwks->get('keys');
        foreach (is_array($list) ? $list : [] as $k) {
            if ($k instanceof JsonObject) {
                $keys[] = $k;
            }
        }
        $kid = $header->get('kid');
        $jwk = null;
        if (Json::truthy($kid)) {
            foreach ($keys as $k) {
                if (Json::pyEq($k->get('kid'), $kid)) {
                    $jwk = $k;
                    break;
                }
            }
        } elseif (count($keys) === 1) {
            $jwk = $keys[0];
        }
        if ($jwk === null) {
            throw $bad('no matching key in the JWKS');
        }
        try {
            $ok = self::verifyJws($alg, $jwk, "$headB.$bodyB", $sig);
        } catch (\Throwable $e) {
            throw $bad($e->getMessage() !== '' ? $e->getMessage() : 'key or signature is malformed');
        }
        if (!$ok) {
            throw $bad('signature does not verify');
        }
        try {
            $claims = Json::decodeBytes(self::b64uDec($bodyB));
        } catch (\Throwable) {
            $claims = null;
        }
        if (!$claims instanceof JsonObject) {
            throw $bad('malformed claims');
        }
        $aud = $claims->get('aud');
        if ($claims->get('iss') !== $issuer) {
            throw $bad('wrong issuer');
        }
        if (!($aud === $audience || (is_array($aud) && in_array($audience, $aud, true)))) {
            throw $bad('wrong audience');
        }
        // OIDC Core 3.1.3.7: a token issued to another client is not ours even when
        // our client id is among its audiences (access tokens of other clients are)
        if ($claims->has('azp') && $claims->get('azp') !== $audience) {
            throw $bad('issued to another client (azp)');
        }
        if (is_array($aud) && count($aud) > 1 && !$claims->has('azp')) {
            throw $bad('several audiences and no azp claim');
        }
        $exp = $claims->get('exp');
        if (!Num::isInt($exp)) {
            throw $bad('no exp claim');
        }
        if (Num::cmp($exp, $now) <= 0) {
            throw $bad('ID token has expired');
        }
        $nbf = $claims->get('nbf');
        if ((Num::isInt($nbf) || is_bool($nbf)) && Num::cmp(Num::of($nbf), Num::add($now, 60)) > 0) {
            throw $bad('ID token is not valid yet');
        }
        return $claims;
    }
}
