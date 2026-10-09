<?php
declare(strict_types=1);

namespace SmartDelegate;

/** The signing key of this engine (optional) and the public keys it accepts tokens from. */
final class Keys
{
    /** sodium secret key (64 bytes), or null for a verify-only engine */
    private ?string $secret = null;
    public ?string $kid = null;
    public ?string $publicB64 = null;
    /** @var array<string,string> key id => 32 raw public key bytes */
    private array $verifiers = [];

    /** @param list<string> $trustedPublicB64 */
    public function __construct(?string $privateB64, array $trustedPublicB64)
    {
        if ($privateB64 !== null && $privateB64 !== '') {
            [$this->secret, $raw] = Bundle::loadPrivate($privateB64);
            $this->kid = substr(hash('sha256', $raw), 0, 16);
            $this->publicB64 = base64_encode($raw);
            $this->verifiers['k' . $this->kid] = $raw;
        }
        foreach ($trustedPublicB64 as $b) {
            $raw = Bundle::loadPublic($b);
            $this->verifiers['k' . substr(hash('sha256', $raw), 0, 16)] = $raw;
        }
    }

    public function __destruct()
    {
        if ($this->secret !== null) {
            sodium_memzero($this->secret);
        }
    }

    public function canSign(): bool
    {
        return $this->secret !== null;
    }

    public function sign(JsonObject $claims): string
    {
        if ($this->secret === null) {
            throw new EngineError('no_signing_key', 'this engine can verify tokens but not issue them');
        }
        $head = Tokens::b64u(Json::compact(new JsonObject(['typ' => 'JWT', 'alg' => 'EdDSA', 'kid' => $this->kid])));
        $body = Tokens::b64u(Json::compact($claims));
        return "$head.$body." . Tokens::b64u(sodium_crypto_sign_detached("$head.$body", $this->secret));
    }

    /**
     * Signature, issuer, audience and shape. Time and revocation belong to the
     * engine, which owns the clock.
     *
     * @throws TokenInvalid with the reason
     */
    public function verify(string $token, string $issuer): JsonObject
    {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                throw new \UnexpectedValueException('not three parts');
            }
            [$headB, $bodyB, $sigB] = $parts;
            $header = Json::decodeBytes(Tokens::b64uDec($headB));
            $sig = Tokens::b64uDec($sigB);
        } catch (\Throwable) {
            throw new TokenInvalid('token is not a JWT');
        }
        if (!$header instanceof JsonObject || $header->get('alg') !== 'EdDSA') {
            throw new TokenInvalid('token algorithm is not EdDSA');
        }
        $kid = $header->get('kid');
        if (!is_string($kid)) {
            throw new TokenInvalid('token has no key id');
        }
        $key = $this->verifiers['k' . $kid] ?? null;
        if ($key === null) {
            throw new TokenInvalid('token was signed by an unknown key');
        }
        $ok = false;
        try {
            $ok = strlen($sig) === SODIUM_CRYPTO_SIGN_BYTES && sodium_crypto_sign_verify_detached($sig, "$headB.$bodyB", $key);
        } catch (\Throwable) {
            $ok = false;
        }
        if (!$ok) {
            throw new TokenInvalid('token rejected: bad signature');
        }
        try {
            $claims = Json::decodeBytes(Tokens::b64uDec($bodyB));
            $good = $claims instanceof JsonObject;
            foreach (['iss', 'aud', 'sub', 'jti'] as $k) {
                $good = $good && is_string($claims->get($k));
            }
            foreach (['iat', 'exp'] as $k) {
                $good = $good && Num::isInt($claims->get($k));
            }
            $good = $good && $claims->get('act') instanceof JsonObject;
            if ($good && $claims->has('anc')) {
                $anc = $claims->get('anc');
                $good = is_array($anc);
                foreach ($good ? $anc : [] as $x) {
                    $good = $good && is_string($x);
                }
            } elseif ($good) {
                $claims->set('anc', []);
            }
            if ($good && $claims->has('role')) {
                $good = is_string($claims->get('role')) && $claims->get('role') !== '';
            }
            if ($good && $claims->has('grp')) {
                $grp = $claims->get('grp');
                $good = is_array($grp);
                foreach ($good ? $grp : [] as $g) {
                    $good = $good && $g instanceof JsonObject && is_string($g->get('type')) && is_string($g->get('id'));
                }
            }
            if ($good && $claims->has('lim')) {
                // budgets of ancestor tokens: {token id: {currency: non-negative integer}}. A list is not an object.
                $lim = $claims->get('lim');
                $good = $lim instanceof JsonObject;
                foreach ($good ? $lim->m : [] as $b) {
                    $good = $good && $b instanceof JsonObject;
                    foreach ($good ? $b->m : [] as $v) {
                        $good = $good && Num::isInt($v) && Num::cmp($v, 0) >= 0;
                    }
                }
            }
            if ($good) {
                if (!$claims->has('cap')) {
                    throw new \UnexpectedValueException('no cap');
                }
                $claims->set('cap', Cap::fromJson($claims->get('cap'))->toJson());
            }
        } catch (\Throwable) {
            $good = false;
        }
        if (!$good) {
            throw new TokenInvalid('token rejected: malformed claims');
        }
        if ($claims->get('aud') !== Tokens::AUDIENCE) {
            throw new TokenInvalid('token rejected: wrong audience');
        }
        if ($claims->get('iss') !== $issuer) {
            throw new TokenInvalid('token rejected: wrong issuer');
        }
        return $claims;
    }
}
