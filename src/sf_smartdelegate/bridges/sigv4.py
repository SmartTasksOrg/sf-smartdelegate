"""AWS Signature Version 4 for one request, standard library only.

Written from https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
(canonical request, string to sign, key derivation, Authorization header) and checked in
tests/ against the worked examples published at
https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
(GET Object, GET Bucket Lifecycle and List Objects: the signatures match).

Scope: header-based signing of a request whose body is in memory. No query-string
(presigned) signing, no chunked uploads, no SigV4a. The path is percent-encoded once, which
is right for S3 and for the root path "/" that the JSON-protocol services use;
# UNVERIFIED: services other than S3 are documented elsewhere as wanting the path encoded
# twice; that only matters for paths with reserved characters, which this package never sends.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import urllib.parse

from . import BridgeError

_UNRESERVED = "-._~"


def _enc(s: str, slash: bool = False) -> str:
    return urllib.parse.quote(s, safe=_UNRESERVED + ("/" if slash else ""))


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def canonical_request(method: str, url: str, headers: dict, body: bytes) -> tuple:
    """(canonical request text, signed header names). `headers` must already
    hold everything to be signed, including host and x-amz-date."""
    p = urllib.parse.urlsplit(url)
    pairs = sorted((_enc(k), _enc(v)) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True))
    query = "&".join(f"{k}={v}" for k, v in pairs)
    low = {k.lower().strip(): " ".join(str(v).split()) for k, v in headers.items()}
    signed = ";".join(sorted(low))
    canon_headers = "".join(f"{k}:{low[k]}\n" for k in sorted(low))
    payload = low.get("x-amz-content-sha256") or hashlib.sha256(body or b"").hexdigest()
    path = _enc(urllib.parse.unquote(p.path) or "/", slash=True)
    return "\n".join([method.upper(), path, query, canon_headers, signed, payload]), signed


def sign(method: str, url: str, headers: dict, body: bytes | None, *, access_key: str, secret_key: str, region: str,
         service: str, session_token: str | None = None, now: datetime.datetime | None = None) -> dict:
    """The headers to send: the given ones plus Host, X-Amz-Date,
    X-Amz-Security-Token (when a session token is given) and Authorization.
    Every header passed in is signed. The secret key is used only to derive
    the signing key and appears in no return value or exception."""
    if not access_key or not secret_key:
        raise BridgeError("no_credential", "AWS access key or secret key is missing")
    host = urllib.parse.urlsplit(url).netloc
    if not host:
        raise BridgeError("bad_url", "the URL to sign has no host")
    t = (now or datetime.datetime.now(datetime.timezone.utc)).astimezone(datetime.timezone.utc)
    amz_date, date = t.strftime("%Y%m%dT%H%M%SZ"), t.strftime("%Y%m%d")
    out = {k: v for k, v in (headers or {}).items() if k.lower() not in ("host", "x-amz-date", "authorization", "x-amz-security-token")}
    out["Host"], out["X-Amz-Date"] = host, amz_date
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    canon, signed = canonical_request(method, url, out, body or b"")
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canon.encode("utf-8")).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret_key).encode("utf-8"), date), region), service), "aws4_request")
    signature = hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    out["Authorization"] = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope},SignedHeaders={signed},Signature={signature}"
    return out
