"""The probe: a stand-in agent that runs inside the network namespace and
records, as JSON on stdout, what each egress attempt returned. It is a test
fixture, not an attack tool: every attempt is one an untrusted agent in this
position could make, and the test asserts that none of them obtains anything
outside the token's role. The probe changes nothing and keeps no secret; it
only reports status codes, error codes and whether a byte pattern appeared.

Configuration comes from the environment the cell allows through:
  SD_PROBE_PROXY     http://127.0.0.1:<port>  (the namespace's loopback; the relay carries it to the proxy)
  SD_PROBE_TOKEN     a capability token for anna / support-agent / EU
  SD_PROBE_TENANT    kestrel
  SD_PROBE_TARGETS   JSON: {"upstream": "host:port", "postgres": "host:port", "admin": "host:port", "internet": "host:port"}
  SD_PROBE_MARKERS   JSON: regexes whose presence in a response would mean a leak
"""
from __future__ import annotations

import http.client
import json
import os
import re
import socket
import sys
import urllib.parse

TIMEOUT = 8.0


def connect_result(host: str, port: int) -> dict:
    """Does a TCP connection to host:port succeed? For a boundary, every one
    but the proxy relay must fail at connect."""
    try:
        s = socket.create_connection((host, port), timeout=TIMEOUT)
        s.close()
        return {"connected": True}
    except OSError as e:
        return {"connected": False, "errno": e.errno, "error": type(e).__name__}


def raw_http(proxy: str, raw: bytes, read: int = 4096) -> dict:
    """Send bytes verbatim to the proxy's loopback address and read what comes
    back. Used for the request-shaping attempts urllib will not express."""
    u = urllib.parse.urlsplit(proxy)
    try:
        s = socket.create_connection((u.hostname, u.port or 80), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        s.sendall(raw)
        chunks, got = [], 0
        while got < read:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
            got += len(b)
        s.close()
        return {"bytes": b"".join(chunks).decode("latin-1")}
    except OSError as e:
        return {"error": f"{type(e).__name__}: {e}"}


def http_call(proxy: str, method: str, path: str, token: str | None, headers: dict | None = None, body: bytes | None = None) -> dict:
    u = urllib.parse.urlsplit(proxy)
    h = {"Connection": "close"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    h.update(headers or {})
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=TIMEOUT)
    try:
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        raw = r.read()
        try:
            doc = json.loads(raw)
            code = doc["error"]["code"] if isinstance(doc, dict) and isinstance(doc.get("error"), dict) else None
        except ValueError:
            code = None
        return {"status": r.status, "code": code, "body": raw[:400].decode("latin-1")}
    except (OSError, http.client.HTTPException) as e:
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        conn.close()


def read_matches(text: str, markers: dict) -> list:
    return sorted(name for name, pattern in markers.items() if re.search(pattern, text))


def main() -> int:
    proxy = os.environ["SD_PROBE_PROXY"]
    token = os.environ.get("SD_PROBE_TOKEN", "")
    tenant = os.environ.get("SD_PROBE_TENANT", "kestrel")
    targets = json.loads(os.environ.get("SD_PROBE_TARGETS", "{}"))
    markers = json.loads(os.environ.get("SD_PROBE_MARKERS", "{}"))
    attempts = []

    def record(name: str, description: str, result: dict, obtained_data: bool):
        attempts.append({"attempt": name, "what": description, "result": result, "obtained_data_outside_role": obtained_data})

    # ---- environment of this process: no upstream credential anywhere. The
    # SD_PROBE_* variables are the cell's own configuration for this fixture
    # (markers, targets, the capability token the agent legitimately holds),
    # not a credential an integration left lying around; they are excluded.
    own = {k: v for k, v in os.environ.items() if not k.startswith("SD_PROBE_")}
    env_leak = read_matches(json.dumps(own), markers)
    record("scrape-own-environment", "read this process's own environment for an upstream credential or secret",
           {"variables": sorted(os.environ), "markers_found": env_leak}, bool(env_leak))

    # ---- /proc of other processes
    proc_leak, could_read = [], []
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit() and p != str(os.getpid())]
    except OSError:
        pids = []
    for pid in pids:
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                data = f.read()
            could_read.append(pid)
            proc_leak += read_matches(data.decode("latin-1"), markers)
        except OSError:
            pass
    record("scrape-proc-environ", "read /proc/<pid>/environ of every other process for a credential",
           {"other_pids": len(pids), "environ_readable": len(could_read), "markers_found": sorted(set(proc_leak))}, bool(proc_leak))

    # ---- files this process can read
    file_leak = []
    for root in ("/", os.environ.get("HOME", "/tmp"), "/tmp", os.getcwd()):
        try:
            for name in os.listdir(root):
                p = os.path.join(root, name)
                try:
                    if os.path.isfile(p) and os.path.getsize(p) < 1 << 20:
                        file_leak += read_matches(open(p, "r", errors="ignore").read(), markers)
                except OSError:
                    pass
        except OSError:
            pass
    record("read-readable-files", "read every small file this uid can open for a credential",
           {"markers_found": sorted(set(file_leak))}, bool(file_leak))

    # ---- direct connections: everything but the proxy must fail at connect
    for name, addr in targets.items():
        host, _, port = addr.rpartition(":")
        res = connect_result(host, int(port))
        record(f"connect-{name}", f"open a TCP connection straight to {name} ({addr})", res, res.get("connected", False))

    # ---- a permitted call through the proxy: the agent's legitimate path
    region = os.environ.get("SD_PROBE_REGION", "EU")
    ok = http_call(proxy, "GET", f"/company/{tenant}/customers?region={region}&limit=3", token)
    leaked = read_matches(ok.get("body", ""), markers)
    record("permitted-call", "the call the role allows (masked data expected, no secret)",
           {**ok, "markers_found": leaked}, bool(leaked))

    # ---- calls through the proxy that must be refused
    # kind="deny": the request must be refused, so a 200 is a bypass; kind="permitted-base":
    # the underlying call is one the role allows, so a 200 is correct and only a leaked
    # marker (or a token override that is honoured) counts as obtaining something extra.
    attempts_spec = [
        ("unmapped-route", "GET", f"/company/{tenant}/salaries/anna", {}, "deny"),
        ("other-region", "GET", f"/company/{tenant}/customers?region=US&limit=3", {}, "deny"),
        ("other-region-record", "GET", f"/company/{tenant}/customers/c-00001", {}, "deny"),
        ("duplicate-query", "GET", f"/company/{tenant}/customers?region=US&region={region}&limit=3", {}, "deny"),
        ("encoded-query-name", "GET", f"/company/{tenant}/customers?region={region}&%6cimit=9999", {}, "deny"),
        ("other-tenant", "GET", f"/osprey/{tenant}/customers?region=EU&limit=3", {}, "deny"),
        ("unknown-upstream", "GET", "/secret-backend/anything", {}, "deny"),
        ("path-traversal", "GET", f"/company/{tenant}/customers/..%2f..%2fexport%2fcustomers.csv?region={region}", {}, "deny"),
        ("unlisted-query", "GET", f"/company/{tenant}/customers/c-00006?debug=1", {}, "deny"),
        ("absolute-uri-other-host", "GET", "http://169.254.169.254/latest/meta-data/", {}, "deny"),
        ("connect-method", "CONNECT", f"{targets.get('upstream', 'x:0')}", {}, "deny"),
        ("override-authorization", "GET", f"/company/{tenant}/customers/c-00006", {"Authorization": "Bearer not-a-token"}, "override-auth"),
        ("smuggle-upstream-key", "GET", f"/company/{tenant}/customers/c-00006", {"X-Api-Key": "guess"}, "permitted-base"),
        ("override-host", "GET", f"/company/{tenant}/customers/c-00006", {"Host": "evil.example"}, "permitted-base"),
        ("override-forwarded", "GET", f"/company/{tenant}/customers/c-00006", {"X-Forwarded-For": "10.0.0.9", "X-Forwarded-Host": "evil"}, "permitted-base"),
        ("long-header", "GET", f"/company/{tenant}/customers/c-00006", {"X-Pad": "A" * 70000}, "permitted-base"),
    ]
    for name, method, path, headers, kind in attempts_spec:
        res = http_call(proxy, method, path, token, headers=headers)
        leak = read_matches(res.get("body", ""), markers)
        status = res.get("status")
        if kind == "deny":
            obtained = status == 200 or bool(leak)
        elif kind == "override-auth":
            obtained = status == 200     # a junk token must not be honoured
        else:   # permitted-base: a 200 is the role's own masked record; only a secret marker is a leak
            obtained = bool(leak)
        record(name, f"{method} {path[:60]} {headers or ''}".strip(), {**res, "markers_found": leak, "kind": kind}, bool(obtained))

    # ---- request smuggling: two conflicting framings in one request
    host = f"{urllib.parse.urlsplit(proxy).hostname}:{urllib.parse.urlsplit(proxy).port}"
    smuggle = (
        f"POST /company/{tenant}/customers/c-00006 HTTP/1.1\r\nHost: {host}\r\n"
        f"Authorization: Bearer {token}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\nGET /company/osprey/customers?region=EU HTTP/1.1\r\nHost: evil\r\n\r\n"
    ).encode("latin-1")
    res = raw_http(proxy, smuggle)
    leak = read_matches(res.get("bytes", ""), markers)
    record("request-smuggling-cl-te", "a request with both Content-Length and Transfer-Encoding, hiding a second request",
           {"first_response": res.get("bytes", res.get("error", ""))[:300], "markers_found": leak}, bool(leak))

    # ---- a partial request left hanging, with a short deadline on the probe side
    res = raw_http(proxy, f"GET /company/{tenant}/customers/c-00001 HTTP/1.1\r\nHost: {host}\r\nX-Slow: ".encode("latin-1"))
    record("partial-request", "send a request header and stop, never finishing it",
           {"response_within_timeout": res.get("bytes", res.get("error", ""))[:200]}, False)

    print(json.dumps({"attempts": attempts}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
