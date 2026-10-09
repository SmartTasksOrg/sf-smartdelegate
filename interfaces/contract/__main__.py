"""Run the contract checks against your implementations.

    python -m interfaces.contract --identity mypkg.idp:factory --enforcement mypkg.pep:factory
    python -m interfaces.contract --reference            every check against the reference implementations
    python -m interfaces.contract --list [--json]        the checks, and what each factory receives

Options, one per interface: --identity --directory --roles --enforcement
--runtime --approval --audit --revocation. Each takes the dotted path of a
factory: `package.module:name` or `package.module.name`. --only ID[,ID...]
runs just those checks. --json prints the results as JSON.

Run it from the repository root with the package importable, for example
`PYTHONPATH=src:. python -m interfaces.contract ...`. The kit works in a
temporary directory on spec/conformance. Its only network use is one
connection attempt to a closed loopback port (the "engine unreachable" check).

Exit status: 0 every check passed, 1 at least one failed, 2 usage.
"""
from __future__ import annotations

import importlib
import json
import sys

from . import CHECKS, FACTORY_ARGUMENTS, run


def resolve(path: str):
    module, name = path.split(":", 1) if ":" in path else (path.rpartition(".")[0], path.rpartition(".")[2])
    if not module or not name:
        raise ValueError(f"'{path}' is not package.module:name")
    obj = getattr(importlib.import_module(module), name)
    if not callable(obj):
        raise ValueError(f"'{path}' is not callable")
    return obj


def main(argv: list) -> int:
    if not argv or "--help" in argv or "-h" in argv:
        print(__doc__)
        return 0 if argv else 2
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    if argv == ["--list"]:
        if as_json:
            print(json.dumps({"factories": FACTORY_ARGUMENTS, "checks": [{"id": c.id, "interface": c.interface, "title": c.title} for c in CHECKS]}, indent=2))
        else:
            for name, text in FACTORY_ARGUMENTS.items():
                print(f"--{name}\n    {text}")
                for c in CHECKS:
                    if c.interface == name:
                        print(f"    {c.id:<32} {c.title}")
        return 0
    targets, only, i = {}, None, 0
    try:
        if argv == ["--reference"]:
            from ..reference import FACTORIES
            targets = dict(FACTORIES)
        else:
            while i < len(argv):
                flag = argv[i]
                if not flag.startswith("--") or i + 1 >= len(argv):
                    raise ValueError(f"unexpected argument '{flag}'")
                if flag == "--only":
                    only = [x for x in argv[i + 1].split(",") if x]
                elif flag[2:] in FACTORY_ARGUMENTS:
                    targets[flag[2:]] = resolve(argv[i + 1])
                else:
                    raise ValueError(f"unknown option '{flag}'")
                i += 2
            if not targets:
                raise ValueError("name at least one implementation, e.g. --enforcement mypkg.pep:factory")
    except (ValueError, ImportError, AttributeError) as e:
        print(f"interfaces.contract: {e}", file=sys.stderr)
        return 2
    results = [r for name, factory in targets.items() for r in run(name, factory, only)]
    if as_json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
    else:
        for r in results:
            print(f"{'ok  ' if r.ok else 'FAIL'} {r.id:<32} {r.title}" + ("" if r.ok else f"\n       {r.detail}"))
        print(f"{len(results)} checks, {sum(1 for r in results if not r.ok)} failed")
    return 0 if results and all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
