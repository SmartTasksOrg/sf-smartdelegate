#!/usr/bin/env python3
"""Which capability tokens of a user are still alive, according to the audit log.

    smartdelegate audit tail -n 5000 | python3 skills/smartdelegate-offboard/scripts/live_tokens.py --user alice
    smartdelegate audit tail -n 5000 | python3 skills/smartdelegate-offboard/scripts/live_tokens.py --user alice --now 1700000000

Reads JSON Lines from standard input, as `smartdelegate audit tail` prints
them. A token is counted as alive when it was issued or exchanged for that
user, has not expired, is not revoked itself or through an ancestor, and was
issued after the user's last revoke cut-off. After an offboarding the answer
must be 0.

Limits: it sees only the records it is given (use an -n larger than the
number of records since the oldest token that can still be alive: the largest
max_ttl is the bound); it knows nothing of engines with another state
directory, nor of cloud credentials made from a token.

Reads only; standard library only. Exit status: 0 no live token, 3 at least
one, 2 usage.
"""
from __future__ import annotations

import json
import sys
import time


def live(records: list, user: str, now: int) -> list:
    revoked = {r.get("token_id") for r in records if r.get("event") == "token_revoked"}
    cutoff = max((r.get("issued_up_to", 0) for r in records if r.get("event") == "user_revoked" and r.get("user") == user), default=None)
    out = []
    for r in records:
        if r.get("event") not in ("token_issued", "token_exchanged") or r.get("user") != user:
            continue
        if r.get("exp", 0) <= now or r.get("token_id") in revoked or revoked & set(r.get("ancestors") or []):
            continue
        if cutoff is not None and r.get("ts", 0) <= cutoff:
            continue
        out.append({"token_id": r.get("token_id"), "chain": r.get("chain"), "role": r.get("role"), "task": r.get("task"),
                    "issued": r.get("ts"), "expires_in": r.get("exp", 0) - now})
    return out


def main(argv: list) -> int:
    if "--help" in argv or "-h" in argv:
        print(__doc__)
        return 0
    try:
        user = argv[argv.index("--user") + 1]
        now = int(argv[argv.index("--now") + 1]) if "--now" in argv else int(time.time())
        if set(argv) - {"--user", user, "--now", str(now)}:
            raise ValueError
    except (ValueError, IndexError):
        print(__doc__)
        return 2
    records = []
    for line in sys.stdin.read().split("\n"):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict):
            records.append(r)
    tokens = live(records, user, now)
    revocations = [r for r in records if r.get("event") == "user_revoked" and r.get("user") == user]
    print(json.dumps({"user": user, "user_revoked_records": len(revocations),
                      "last_cutoff": max((r.get("issued_up_to", 0) for r in revocations), default=None),
                      "live_tokens": tokens}, indent=2))
    return 3 if tokens else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
