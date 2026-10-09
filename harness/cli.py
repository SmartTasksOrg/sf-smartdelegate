"""Command line of the small scenario harness.

  python -m harness list [-v]
  python -m harness run [--scenarios 01,07|all] [--instances K] [--seed S] [--bundle DIR] [--scenario-dir DIR]
                        [--backend inprocess|url:http://host:port] [--admin-key-env VAR] [--pep-key-env VAR] [--out DIR]

Run from the repository root with PYTHONPATH=src, or as `python harness/run.py ...`.
Exit status: 0 every check passed; 1 at least one did not; 2 the harness could not run.
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from . import report
from .core import COMPANY, Company, HarnessError, Run, load_scenarios, needs_clock, open_backend


def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(prog="harness", description="Small scenario harness for SmartDelegate.")
    sub = p.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list", help="list the scenarios")
    ls.add_argument("-v", "--verbose", action="store_true")
    run = sub.add_parser("run", help="run scenarios against an engine and check them")
    run.add_argument("--scenarios", default="all", help="comma-separated ids or numbers (01,07), or all")
    run.add_argument("--instances", type=int, default=None, help="scenario instances to run, round-robin (default: each selected scenario once)")
    run.add_argument("--seed", type=int, default=1, help="chooses which people of the bundle play each scenario")
    run.add_argument("--backend", default="inprocess", help="inprocess, or url:http://host:port for a daemon that is running")
    run.add_argument("--admin-key-env", default=None, help="url: backend: environment variable with the admin key (default SMARTDELEGATE_ADMIN_KEY)")
    run.add_argument("--pep-key-env", default=None, help="url: backend: environment variable with the pep key (default SMARTDELEGATE_PEP_KEY)")
    run.add_argument("--bundle", default=str(COMPANY), help="the bundle the scenarios are about (default examples/company)")
    run.add_argument("--out", default=None, help="directory for report.json and report.html (default: a new temporary directory)")
    for x in (ls, run):
        x.add_argument("--scenario-dir", default=None, help="read scenarios from this directory instead of harness/scenarios")
    args = p.parse_args(argv)
    try:
        scenarios = load_scenarios(args.scenario_dir) if args.scenario_dir else load_scenarios()
        if args.cmd == "list":
            for sid, doc in sorted(scenarios.items()):
                print(f"{sid:28s} {len(doc['steps']):3d} steps  units: {', '.join(doc['units'])}{'  [needs the test clock]' if needs_clock(doc) else ''}")
                if args.verbose:
                    print(f"    {doc['name']}: {doc['description']}")
            print(f"{len(scenarios)} scenarios")
            return 0
        if not scenarios:
            raise HarnessError("no scenario files")
        backend = open_backend(args.backend, args.bundle, args.admin_key_env, args.pep_key_env)
        try:
            r = Run(backend, Company(args.bundle), scenarios, args.seed)
            r.run(args.scenarios, args.instances)
        finally:
            backend.close()
    except HarnessError as e:
        print(f"harness: {e}")
        return 2
    rep = report.build(r, {"scenarios": args.scenarios, "instances": args.instances, "seed": args.seed, "backend": args.backend})
    for s in rep["scenarios"]:
        print(f"{s['status']:4s}  {s['id']:28s} {s['steps']:3d} steps" + (f"  ({s['why']})" if s.get("why") else ""))
    t = rep["totals"]
    print(f"backend {rep['backend']['name']} ({rep['backend']['implementation']} engine): {t['instances']} instances, {t['engine_calls']} requests, "
          f"{t['decisions']} decisions in {t['wall_seconds']} s; audit records: {rep['audit'].get('records', 0)} ({rep['audit'].get('decisions_matched', 0)} decisions matched)")
    for v in rep["violations"][:10]:
        print(f"  VIOLATION {v['invariant']} {v['scenario']} instance {v['instance']} step {v['step']}: {v['detail']}")
    for e in rep["harness_errors"]:
        print(f"  HARNESS ERROR {e}")
    print(f"violations: {len(rep['violations'])}; harness errors: {len(rep['harness_errors'])}")
    print(f"verdict: {rep['verdict']}")
    paths = report.write(rep, args.out or tempfile.mkdtemp(prefix="smartdelegate-harness-report-"))
    print("reports" + ("" if args.out else " (no --out given: a new temporary directory)") + ":")
    print(f"  open this one   {paths['html']}")
    print(f"  for machines    {paths['json']}")
    return rep["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
