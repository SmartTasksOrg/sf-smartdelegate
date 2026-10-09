"""Run live test modules and turn the outcome into the exit status live/run.sh promises.

    python3 -m live.runner live.upstream.test_live_upstream [more modules or test ids]

    0   something ran and nothing failed
    1   a test failed or raised
    3   nothing ran: every test was skipped (the reasons are printed)

A test marked `@finding("L-n")` is an expected failure tied to live/FINDINGS.md. When such a test
passes, unittest calls it an "unexpected success" and fails the run. Here it is reported as

    FIXED? finding L-n no longer reproduces: <test>

and the run still exits 0, provided every other test passed: a finding that stopped reproducing is
news, not a regression. Remove the mark (and update FINDINGS.md) to make the test an ordinary one.
"""
from __future__ import annotations

import sys
import unittest


def main(argv=None) -> int:
    names = list(sys.argv[1:] if argv is None else argv)
    if not names:
        print(__doc__, file=sys.stderr)
        return 2
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    fixed = []
    for test in result.unexpectedSuccesses:
        method = getattr(test, getattr(test, "_testMethodName", ""), None)
        fixed.append((getattr(method, "finding", "?"), test.id()))
    for fid, tid in sorted(fixed):
        print(f"FIXED? finding {fid} no longer reproduces: {tid}", file=sys.stderr)
    failed = len(result.failures) + len(result.errors)
    ran = result.testsRun - len(result.skipped)
    reasons = sorted({reason for _, reason in result.skipped})
    print(f"RESULT ran={max(ran, 0)} failed={failed} skipped={len(result.skipped)} expected_failures={len(result.expectedFailures)} fixed={len(fixed)}", file=sys.stderr)
    if failed:
        return 1
    if ran <= 0:
        for r in reasons:
            print(f"SKIPPED: {r}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
