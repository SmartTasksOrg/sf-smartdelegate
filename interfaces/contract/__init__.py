"""The contract test kit: `python -m interfaces.contract --help`.

    from interfaces.contract import run, contract_testcase
    results = run("identity", my_factory)                       # -> [Result(id, interface, title, ok, detail)]
    class MyPepContract(contract_testcase("enforcement", my_factory)): pass     # unittest / pytest collect it
"""
from __future__ import annotations

import unittest

from .kit import CHECKS, FACTORY_ARGUMENTS, Check, Result, Violation, checks_for, run

__all__ = ["run", "contract_testcase", "checks_for", "CHECKS", "FACTORY_ARGUMENTS", "Check", "Result", "Violation"]


def contract_testcase(interface: str, factory) -> type:
    """A unittest.TestCase class with one test method per contract check of
    `interface`, run against `factory`. Subclass it (or assign it to a name in
    your test module) and unittest or pytest will collect it."""
    if not checks_for(interface):
        raise ValueError(f"no interface named '{interface}'; choose from {', '.join(sorted(FACTORY_ARGUMENTS))}")

    def method(check_id: str):
        def test(self):
            result = run(interface, factory, only=[check_id])[0]
            if not result.ok:
                self.fail(f"{result.id}: {result.title}\n  {result.detail}")
        test.__doc__ = check_id
        return test

    body = {"test_" + c.id.replace("-", "_"): method(c.id) for c in checks_for(interface)}
    return type(f"{interface.capitalize()}Contract", (unittest.TestCase,), body)
