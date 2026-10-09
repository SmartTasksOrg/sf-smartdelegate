#!/usr/bin/env python3
"""What can a container on the agent network reach? Run by the `agent`
service of docker/docker-compose.yml, which sits on an `internal: true`
network together with the HTTP proxy and nothing else.

    AGENT_ALLOWED     host:port that must answer            (http-proxy:8182)
    AGENT_FORBIDDEN   comma-separated host:port that must NOT be reachable:
                      the upstream, the database, the daemon's admin API, the
                      identity provider (by name and by address) and the internet

Passes (exit 0) when the proxy answers HTTP and refuses a request without a
capability token, and every forbidden address fails to resolve or to connect.
Exit 1 otherwise. Standard library only. It holds no credential: the agent
has none.

This is a reachability check of the Compose topology. The request-level
boundary test (what a token holder can and cannot get through the proxy) is
live/boundary, run with `live/run.sh boundary` on Linux as root.

UNTESTED in a container (no Docker daemon where it was written); the script
was run on Linux against local listeners.
"""
import http.client
import json
import os
import socket
import sys
import time

TIMEOUT = 5.0


def split(target):
    host, _, port = target.strip().rpartition(":")
    return host, int(port)


def connect(host, port):
    """-> (reached, why)"""
    try:
        s = socket.create_connection((host, port), timeout=TIMEOUT)
        s.close()
        return True, "connected"
    except socket.gaierror as e:
        return False, "does not resolve (%s)" % e.strerror
    except OSError as e:
        return False, "%s (%s)" % (type(e).__name__, e.strerror or e)


def main():
    allowed = os.environ.get("AGENT_ALLOWED", "http-proxy:8182")
    forbidden = [t for t in os.environ.get("AGENT_FORBIDDEN", "").split(",") if t.strip()]
    failures = 0

    host, port = split(allowed)
    answer = None
    for _ in range(30):                      # the proxy may still be starting
        try:
            c = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
            c.request("GET", "/company/kestrel/customers")
            r = c.getresponse()
            answer = (r.status, r.read(2000).decode("utf-8", "replace"))
            c.close()
            break
        except OSError:
            time.sleep(1)
    if answer is None:
        print("FAIL  %s: the proxy does not answer" % allowed)
        failures += 1
    else:
        try:
            code = (json.loads(answer[1]).get("error") or {}).get("code")
        except ValueError:
            code = None
        ok = answer[0] == 401 and code == "token_invalid"
        print("%s  %s: reachable; a request without a token gets %s %s" % ("PASS" if ok else "FAIL", allowed, answer[0], code))
        failures += not ok

    if not forbidden:
        print("FAIL  AGENT_FORBIDDEN is empty: nothing was checked")
        failures += 1
    for target in forbidden:
        h, p = split(target)
        reached, why = connect(h, p)
        print("%s  %s: %s" % ("FAIL" if reached else "PASS", target.strip(), "REACHABLE from the agent network" if reached else "not reachable: " + why))
        failures += reached
    print("agent network check: %s" % ("FAILED" if failures else "passed: the agent reaches the proxy and nothing else that was tried"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
