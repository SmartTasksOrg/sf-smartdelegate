"""Capability tokens: EdDSA-signed JWTs with an RFC 8693 `act` delegation
chain and a `cap` claim that can only be narrowed on each hop."""
from __future__ import annotations

import base64
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from . import bundle
from .canon import sha256_hex
from .errors import EngineError

AUDIENCE = "smartdelegate"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


_B64U = re.compile(r"[A-Za-z0-9_-]+")


def b64u_dec(text: str) -> bytes:
    # strict: exactly the URL-safe alphabet, no padding. The standard library
    # skips characters outside the alphabet, which would give one token many
    # spellings.
    if not isinstance(text, str) or not _B64U.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---- capability ------------------------------------------------------------

def _str_list(v, what: str) -> list:
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise EngineError("invalid_cap", f"{what} must be a list of strings")
    return list(v)


class Cap:
    """actions / resources: names with an optional single trailing `*`.
    resources are `<path>/<id>`. deny_labels / deny_fields: what this token
    can never see, whatever policy says. budget: currency -> total spend in
    minor units."""

    def __init__(self, actions=None, resources=None, deny_labels=None, deny_fields=None, budget=None):
        self.actions = _str_list(actions, "cap.actions")
        self.resources = _str_list(resources, "cap.resources")
        self.deny_labels = _str_list(deny_labels, "cap.deny_labels")
        self.deny_fields = _str_list(deny_fields, "cap.deny_fields")
        budget = budget or {}
        if not isinstance(budget, dict) or not all(isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) for k, v in budget.items()):
            raise EngineError("invalid_cap", "cap.budget must map currency to an integer amount in minor units")
        self.budget = dict(budget)

    @classmethod
    def from_json(cls, v) -> "Cap":
        if not isinstance(v, dict):
            raise EngineError("invalid_cap", "cap must be an object")
        unknown = set(v) - {"actions", "resources", "deny_labels", "deny_fields", "budget"}
        if unknown:
            # a misspelt key must not silently become "no restriction"
            raise EngineError("invalid_cap", f"unknown cap field(s): {', '.join(sorted(unknown))}")
        return cls(v.get("actions"), v.get("resources"), v.get("deny_labels"), v.get("deny_fields"), v.get("budget"))

    @classmethod
    def unrestricted(cls) -> "Cap":
        return cls(["*"], ["*"])

    def to_json(self) -> dict:
        return {"actions": self.actions, "resources": self.resources, "deny_labels": self.deny_labels,
                "deny_fields": self.deny_fields, "budget": self.budget}

    def validate(self) -> None:
        for p in self.actions + self.resources:
            if not p or "*" in p[:-1]:
                raise EngineError("invalid_cap", f"pattern '{p}': only one trailing * is allowed")
        if any(v < 0 for v in self.budget.values()):
            raise EngineError("invalid_cap", "budget cannot be negative")

    def allows_action(self, action: str) -> bool:
        return any(_matches(p, action) for p in self.actions)

    def allows_resource(self, path: str, id: str) -> bool:
        s = f"{path}/{id}"
        return any(_matches(p, s) for p in self.resources)

    def check_narrower_than(self, parent: "Cap") -> None:
        """Raises `widening` unless self grants nothing the parent does not."""
        for a in self.actions:
            if not any(_covers(p, a) for p in parent.actions):
                raise EngineError("widening", f"action '{a}' is not covered by the parent token")
        for r in self.resources:
            if not any(_covers(p, r) for p in parent.resources):
                raise EngineError("widening", f"resource '{r}' is not covered by the parent token")
        for l in parent.deny_labels:
            if l not in self.deny_labels:
                raise EngineError("widening", f"label '{l}' is denied by the parent and must stay denied")
        for f in parent.deny_fields:
            if f not in self.deny_fields:
                raise EngineError("widening", f"field '{f}' is denied by the parent and must stay denied")
        for cur, amount in self.budget.items():
            if cur not in parent.budget:
                raise EngineError("widening", f"the parent token has no {cur} budget to pass on")
            if amount > parent.budget[cur]:
                raise EngineError("widening", f"budget {amount} {cur} exceeds the parent's {parent.budget[cur]}")


def _matches(pattern: str, s: str) -> bool:
    return s.startswith(pattern[:-1]) if pattern.endswith("*") else pattern == s


matches = _matches


def _covers(parent: str, child: str) -> bool:
    """Does `parent` cover every string that `child` covers?"""
    if parent.endswith("*"):
        return child.rstrip("*").startswith(parent[:-1]) if child.endswith("*") else child.startswith(parent[:-1])
    return (not child.endswith("*")) and parent == child


# ---- claims ----------------------------------------------------------------

def act_for(chain: list) -> dict:
    """RFC 8693 actor chain: the current actor is outermost."""
    act = None
    for agent in chain:
        act = {"sub": f"agent:{agent}"} if act is None else {"sub": f"agent:{agent}", "act": act}
    return act


def chain_of(claims: dict) -> list:
    """Agents root-first: ["support-bot", "refund-helper"]."""
    out, cur = [], claims.get("act")
    while isinstance(cur, dict) and isinstance(cur.get("sub"), str):
        out.append(cur["sub"][6:] if cur["sub"].startswith("agent:") else cur["sub"])
        cur = cur.get("act")
    return out[::-1]


def user_of(claims: dict) -> str:
    sub = claims.get("sub", "")
    return sub[5:] if sub.startswith("user:") else sub


class Keys:
    def __init__(self, private_b64: str | None, trusted_public_b64: list):
        self._private = None
        self.kid = None
        self.public_b64 = None
        self._verifiers: dict = {}
        if private_b64:
            self._private = bundle.load_private(private_b64)
            raw = bundle.public_raw(self._private)
            self.kid = sha256_hex(raw)[:16]
            self.public_b64 = base64.b64encode(raw).decode()
            self._verifiers[self.kid] = self._private.public_key()
        for b in trusted_public_b64 or []:
            key, raw = bundle.load_public(b)
            self._verifiers[sha256_hex(raw)[:16]] = key

    def can_sign(self) -> bool:
        return self._private is not None

    def sign(self, claims: dict) -> str:
        if self._private is None:
            raise EngineError("no_signing_key", "this engine can verify tokens but not issue them")
        head = b64u(json.dumps({"typ": "JWT", "alg": "EdDSA", "kid": self.kid}, separators=(",", ":")).encode())
        body = b64u(json.dumps(claims, separators=(",", ":")).encode())
        return f"{head}.{body}.{b64u(self._private.sign(f'{head}.{body}'.encode()))}"

    def verify(self, token: str, issuer: str) -> dict:
        """Signature, issuer, audience and shape. Time and revocation belong
        to the engine, which owns the clock. Raises ValueError(reason)."""
        try:
            head_b, body_b, sig_b = token.split(".")
            header = json.loads(b64u_dec(head_b))
            sig = b64u_dec(sig_b)
        except Exception:
            raise ValueError("token is not a JWT") from None
        if not isinstance(header, dict) or header.get("alg") != "EdDSA":
            raise ValueError("token algorithm is not EdDSA")
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise ValueError("token has no key id")
        key = self._verifiers.get(kid)
        if key is None:
            raise ValueError("token was signed by an unknown key")
        try:
            key.verify(sig, f"{head_b}.{body_b}".encode())
        except InvalidSignature:
            raise ValueError("token rejected: bad signature") from None
        try:
            claims = json.loads(b64u_dec(body_b))
            assert isinstance(claims, dict)
            for k in ("iss", "aud", "sub", "jti"):
                assert isinstance(claims[k], str)
            for k in ("iat", "exp"):
                assert isinstance(claims[k], int) and not isinstance(claims[k], bool)
            assert isinstance(claims["act"], dict)
            assert isinstance(claims.get("anc", []), list) and all(isinstance(x, str) for x in claims.get("anc", []))
            claims.setdefault("anc", [])
            assert "role" not in claims or (isinstance(claims["role"], str) and claims["role"])
            assert "grp" not in claims or (isinstance(claims["grp"], list) and all(
                isinstance(g, dict) and isinstance(g.get("type"), str) and isinstance(g.get("id"), str) for g in claims["grp"]))
            lim = claims.get("lim", {})
            assert isinstance(lim, dict) and all(
                isinstance(b, dict) and all(isinstance(c, str) and isinstance(v, int) and not isinstance(v, bool) and v >= 0
                                            for c, v in b.items()) for b in lim.values())
            claims["cap"] = Cap.from_json(claims["cap"]).to_json()
        except Exception:
            raise ValueError("token rejected: malformed claims") from None
        if claims["aud"] != AUDIENCE:
            raise ValueError("token rejected: wrong audience")
        if claims["iss"] != issuer:
            raise ValueError("token rejected: wrong issuer")
        return claims


# ---- OIDC ID tokens --------------------------------------------------------

_HASH = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}


def _int(b64: str) -> int:
    return int.from_bytes(b64u_dec(b64), "big")


def _verify_jws(alg: str, jwk: dict, signing_input: bytes, sig: bytes) -> None:
    if alg in ("RS256", "RS384", "RS512") and jwk.get("kty") == "RSA":
        key = rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
        key.verify(sig, signing_input, padding.PKCS1v15(), _HASH[alg[2:]]())
    elif alg in ("ES256", "ES384") and jwk.get("kty") == "EC":
        curve, size = (ec.SECP256R1(), 32) if alg == "ES256" else (ec.SECP384R1(), 48)
        if len(sig) != 2 * size:
            raise InvalidSignature()
        key = ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), curve).public_key()
        der = utils.encode_dss_signature(int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big"))
        key.verify(der, signing_input, ec.ECDSA(_HASH[alg[2:]]()))
    elif alg == "EdDSA" and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        ed25519.Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"])).verify(sig, signing_input)
    else:
        raise ValueError("unsupported signing algorithm")


def verify_id_token(id_token: str, jwks: dict, issuer: str, audience: str, now: int) -> dict:
    """Verify an OIDC ID token against a static JWKS and return its claims."""
    def bad(msg):
        return EngineError("id_token_invalid", msg)
    try:
        head_b, body_b, sig_b = id_token.split(".")
        header = json.loads(b64u_dec(head_b))
        sig = b64u_dec(sig_b)
        alg = header["alg"]
    except Exception:
        raise bad("not a JWT") from None
    keys = [k for k in (jwks.get("keys") or []) if isinstance(k, dict)]
    kid = header.get("kid")
    jwk = next((k for k in keys if k.get("kid") == kid), None) if kid else (keys[0] if len(keys) == 1 else None)
    if jwk is None:
        raise bad("no matching key in the JWKS")
    try:
        _verify_jws(alg, jwk, f"{head_b}.{body_b}".encode(), sig)
    except InvalidSignature:
        raise bad("signature does not verify") from None
    except Exception as e:
        raise bad(str(e) or "key or signature is malformed") from None
    try:
        claims = json.loads(b64u_dec(body_b))
        assert isinstance(claims, dict)
    except Exception:
        raise bad("malformed claims") from None
    aud = claims.get("aud")
    if claims.get("iss") != issuer:
        raise bad("wrong issuer")
    if not (aud == audience or (isinstance(aud, list) and audience in aud)):
        raise bad("wrong audience")
    # OIDC Core 3.1.3.7: a token issued to another client is not ours even when
    # our client id is among its audiences (access tokens of other clients are)
    if "azp" in claims and claims["azp"] != audience:
        raise bad("issued to another client (azp)")
    if len(aud) > 1 and isinstance(aud, list) and "azp" not in claims:
        raise bad("several audiences and no azp claim")
    exp = claims.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise bad("no exp claim")
    if exp <= now:
        raise bad("ID token has expired")
    nbf = claims.get("nbf")
    if isinstance(nbf, int) and nbf > now + 60:
        raise bad("ID token is not valid yet")
    return claims
