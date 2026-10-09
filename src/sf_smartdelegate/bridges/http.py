"""HTTP plumbing shared by the bridges.

Every network call in `sf_smartdelegate.bridges` goes through a `Transport`:

    transport(method, url, headers, body) -> (status, headers, body)

`headers` in the result has lower-case names. The default, `urllib_transport`,
uses urllib with a timeout, TLS verification on (the standard library
default; it is never switched off here), a response size limit, and refuses a
redirect to another host. Nothing in this module logs or prints, and no
exception message contains a header value, a request body or a query string.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Iterator, Optional

from . import BridgeError

Transport = Callable[[str, str, dict, Optional[bytes]], tuple]

DEFAULT_TIMEOUT = 30
MAX_BODY = 64 * 1024 * 1024
#: upper bound on pages followed for one listing; a looping or endless `next` stops here
MAX_PAGES = 10000
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def origin(url: str) -> tuple:
    """(scheme, host, port) of a URL, lower-cased, with the default port filled in."""
    try:
        p = urllib.parse.urlsplit(url)
        port = p.port
    except ValueError:
        raise BridgeError("bad_url", "a URL could not be parsed") from None
    scheme = (p.scheme or "").lower()
    return scheme, (p.hostname or "").lower(), port or {"https": 443, "http": 80}.get(scheme)


def safe_url(url: str) -> str:
    """The URL without query and fragment, for error messages."""
    try:
        p = urllib.parse.urlsplit(url)
        return f"{p.scheme}://{p.hostname or ''}{':' + str(p.port) if p.port else ''}{p.path}"
    except ValueError:
        return "<unparseable url>"


def check_url(url: str, allow_http: bool = False) -> None:
    """Raises unless the URL is https (or http to a loopback host, or any http
    when `allow_http`). A bearer token must not travel in clear text."""
    scheme, host, _ = origin(url)
    if not host or scheme not in ("https", "http"):
        raise BridgeError("bad_url", f"not an http(s) URL: {safe_url(url)}")
    if scheme == "http" and not (allow_http or host in _LOOPBACK):
        raise BridgeError("insecure_url", f"refusing plain http to {host}; use https")


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if origin(newurl) != origin(req.full_url):
            raise BridgeError("redirect_refused", f"{safe_url(req.full_url)} redirects to another host ({origin(newurl)[1]}); not followed")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def make_transport(timeout: float = DEFAULT_TIMEOUT, allow_http: bool = False) -> Transport:
    """A urllib transport. Guarantees: the request has a timeout; TLS
    certificates are verified; a redirect is followed only to the same scheme,
    host and port; a response over 64 MiB is refused; an HTTP error status is
    returned (not raised) so the caller decides; a connection failure raises
    BridgeError("network") without the URL's query string."""
    opener = urllib.request.build_opener(_SameHostRedirects())

    def transport(method: str, url: str, headers: dict, body: Optional[bytes]) -> tuple:
        check_url(url, allow_http)
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers or {}))
        try:
            with opener.open(req, timeout=timeout) as r:
                data = r.read(MAX_BODY + 1)
                status, got = r.status, _headers(r.headers)
        except urllib.error.HTTPError as e:
            try:
                data = e.read(MAX_BODY + 1)
            except Exception:
                data = b""
            status, got = e.code, _headers(e.headers)
        except BridgeError:
            raise
        except (urllib.error.URLError, OSError, ValueError) as e:
            reason = getattr(e, "reason", None) or e
            raise BridgeError("network", f"{method} {safe_url(url)}: {type(reason).__name__}") from None
        if len(data) > MAX_BODY:
            raise BridgeError("response_too_large", f"{method} {safe_url(url)}: response exceeds {MAX_BODY} bytes")
        return status, got, data

    return transport


def _headers(msg) -> dict:
    out: dict = {}
    for k, v in (msg.items() if msg is not None else []):
        k = k.lower()
        out[k] = f"{out[k]}, {v}" if k in out else v
    return out


#: the default transport: 30 s timeout, https only (http to loopback allowed)
urllib_transport: Transport = make_transport()


def secret_from_env(name: str, env=None) -> str:
    """The value of the environment variable `name`. Secrets reach the bridges
    only this way: the caller names the variable, the value is never written
    to disk, logged, or put in an exception."""
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name or ""):
        raise BridgeError("no_credential", "the name of the environment variable holding the credential is missing or malformed")
    value = (os.environ if env is None else env).get(name)
    if not value:
        raise BridgeError("no_credential", f"environment variable {name} is not set")
    return value.strip()


def bearer(token: str) -> dict:
    """`Authorization: Bearer <token>` as a header dict."""
    return {"Authorization": f"Bearer {token}"}


def request_json(transport: Transport, method: str, url: str, headers: dict | None = None, body: bytes | None = None,
                 *, expect: tuple = (200,)) -> tuple:
    """One request whose answer must be JSON. Returns (value, response
    headers). Raises BridgeError("http_error") for any status not in `expect`
    (the status is in `.detail`; the response body is not put in the message)
    and BridgeError("malformed_response") when the body is not JSON."""
    try:
        status, got, data = transport(method, url, dict(headers or {}), body)
    except BridgeError:
        raise
    except Exception as e:  # a transport must not leak anything through an exception either
        raise BridgeError("network", f"{method} {safe_url(url)}: {type(e).__name__}") from None
    if status not in expect:
        raise BridgeError("http_error", f"{method} {safe_url(url)}: HTTP {status}", {"status": status})
    try:
        return json.loads(data.decode("utf-8")), {str(k).lower(): v for k, v in (got or {}).items()}
    except (ValueError, UnicodeDecodeError, AttributeError):
        raise BridgeError("malformed_response", f"{method} {safe_url(url)}: the response is not JSON") from None


def get_json(transport: Transport, url: str, headers: dict | None = None):
    """GET a JSON document; returns (value, response headers). See request_json."""
    return request_json(transport, "GET", url, headers)


def post_json(transport: Transport, url: str, value, headers: dict | None = None):
    """POST a JSON body; returns (value, response headers). See request_json."""
    h = {"Content-Type": "application/json", **(headers or {})}
    return request_json(transport, "POST", url, h, json.dumps(value, separators=(",", ":")).encode("utf-8"))


def post_form(transport: Transport, url: str, form: dict, headers: dict | None = None):
    """POST application/x-www-form-urlencoded fields; returns the JSON answer.
    Used for OAuth token endpoints: the form may hold a secret, which is why
    errors carry the status only."""
    h = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json", **(headers or {})}
    return request_json(transport, "POST", url, h, urllib.parse.urlencode(form).encode("ascii"))[0]


def with_query(url: str, params: dict) -> str:
    """`url` with `params` added to its query (values are percent-encoded; a list repeats the name)."""
    q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, doseq=True, quote_via=urllib.parse.quote)
    return url + ("&" if "?" in url else "?") + q if q else url


class PageGuard:
    """Guards a pagination loop. `step(marker)` must be called once per page
    with whatever identifies the page (the next URL, a page token, an
    offset). It raises BridgeError("pagination_loop") when a marker repeats
    and BridgeError("pagination_limit") after `max_pages` pages, so a server
    that keeps answering `next` cannot spin the caller forever. `check_next`
    refuses a next link that leaves the origin the listing started on: the
    bearer token would otherwise be sent to whoever the response names."""

    def __init__(self, start_url: str, max_pages: int = MAX_PAGES):
        self.origin = origin(start_url)
        self.max_pages = max_pages
        self.seen: set = set()
        self.pages = 0

    def step(self, marker) -> None:
        self.pages += 1
        if self.pages > self.max_pages:
            raise BridgeError("pagination_limit", f"more than {self.max_pages} pages; giving up rather than return a partial listing")
        if marker in self.seen:
            raise BridgeError("pagination_loop", "the server returned the same next page twice")
        self.seen.add(marker)

    def check_next(self, url) -> str:
        if not isinstance(url, str) or not url:
            raise BridgeError("malformed_response", "the next-page link is not a string")
        if origin(url) != self.origin:
            raise BridgeError("next_link_refused", f"the next-page link points at another host ({origin(url)[1] or '?'}); not followed")
        return url


_LINK = re.compile(r"<([^>]*)>\s*((?:;\s*[^;,]+)*)")


def link_next(headers: dict) -> str | None:
    """The target of rel="next" in an RFC 8288 `Link` header, or None."""
    value = (headers or {}).get("link")
    if not value:
        return None
    for target, params in _LINK.findall(value):
        for p in params.split(";"):
            k, _, v = p.strip().partition("=")
            if k.lower() == "rel" and "next" in v.strip('"').lower().split():
                return target
    return None


def pages_by_link_header(transport: Transport, url: str, headers: dict, *, max_pages: int = MAX_PAGES) -> Iterator[list]:
    """Yields each page (a JSON list) of a listing paginated with `Link:
    <...>; rel="next"` (Okta). The link is followed as given, never rebuilt."""
    guard = PageGuard(url, max_pages)
    while url:
        guard.step(url)
        page, got = get_json(transport, url, headers)
        if not isinstance(page, list):
            raise BridgeError("malformed_response", f"GET {safe_url(url)}: expected a JSON list")
        yield page
        nxt = link_next(got)
        url = guard.check_next(nxt) if nxt else None


def pages_by_next_link(transport: Transport, url: str, headers: dict, *, items: str = "value", next_key: str = "@odata.nextLink",
                       max_pages: int = MAX_PAGES) -> Iterator[list]:
    """Yields each page's `items` list of a listing paginated with a next link
    in the body (Microsoft Graph `@odata.nextLink`, Azure `nextLink`)."""
    guard = PageGuard(url, max_pages)
    while url:
        guard.step(url)
        page, _ = get_json(transport, url, headers)
        if not isinstance(page, dict) or not isinstance(page.get(items), list):
            raise BridgeError("malformed_response", f"GET {safe_url(url)}: expected an object with a '{items}' list")
        yield page[items]
        nxt = page.get(next_key)
        url = guard.check_next(nxt) if nxt is not None else None


def str_field(obj, key: str, what: str) -> str:
    """obj[key] as a non-empty string, else BridgeError("malformed_response")."""
    v = obj.get(key) if isinstance(obj, dict) else None
    if not isinstance(v, str) or not v:
        raise BridgeError("malformed_response", f"{what}: '{key}' is missing or not a string")
    return v
