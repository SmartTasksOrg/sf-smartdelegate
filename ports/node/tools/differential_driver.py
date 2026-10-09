"""Test helper: the Python reference engine as a line-oriented server.

    python3 differential_driver.py   (PYTHONPATH must include <repo>/src)

First line on stdin: the engine config (JSON). Then one JSON array per line,
[op, input]; one JSON result per line on stdout. Tokens are referred to by
the order in which this engine issued them, so that two engines given the
same script can be compared: {"$tok": n} is the n-th token (with "good": the
n-th latest of those issued with "_good": true; with "other": the n-th of the
rest), and "cut", "append", "flip" and "sig_of" damage it.
"""
import json
import sys

from sf_smartdelegate import Engine


def main():
    engine = Engine(json.loads(sys.stdin.readline()))
    tokens = {"all": [], "good": [], "other": []}

    def pick(v):
        which = "good" if v.get("good") is True else "other" if v.get("other") is True else "all"
        lst = tokens[which]
        if not lst:
            return None
        n = v["$tok"]
        return lst[max(0, len(lst) - 1 - n)] if which == "good" else lst[n % len(lst)]

    def resolve(v):
        if isinstance(v, dict):
            if "$tok" in v:
                t = pick(v)
                if t is None:
                    return "no-token-yet"
                if "sig_of" in v:
                    other = tokens["all"][v["sig_of"] % len(tokens["all"])]
                    t = ".".join(t.split(".")[:2] + [other.split(".")[2]])
                if "flip" in v:
                    at = v["flip"] % len(t)
                    t = t[:at] + ("B" if t[at] == "A" else "A") + t[at + 1:]
                if "cut" in v:
                    t = t[:-v["cut"]]
                return t + v.get("append", "")
            return {k: resolve(x) for k, x in v.items()}
        if isinstance(v, list):
            return [resolve(x) for x in v]
        return v

    for line in sys.stdin:
        if not line.strip():
            continue
        op, payload = json.loads(line)
        result = engine.call(op, resolve(payload))
        if result.get("ok") and isinstance(result.get("token"), str):
            tokens["all"].append(result["token"])
            good = isinstance(payload, dict) and payload.get("_good") is True
            tokens["good" if good else "other"].append(result["token"])
        sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
        sys.stdout.flush()


main()
