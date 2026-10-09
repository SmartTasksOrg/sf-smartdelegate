"""Tests of the small scenario harness (harness/) and of the example company bundle (examples/company).

They check that every scenario passes on the Python engine, in process and through
the REST daemon, and that each of the five checks reports an engine that gives a
wrong answer. The wrong answers come from a wrapper in this file that changes what
the real engine returned.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import ENV, ROOT, Daemon

sys.path.insert(0, str(ROOT))
from harness import cli, report  # noqa: E402
from harness.core import COMPANY, SCENARIOS, Company, InProcess, Run, load_scenarios  # noqa: E402

EXPIRY = {"id": "90_expiry", "name": "Expiry", "description": "A token is used after it has expired.", "units": ["support"], "requires": ["test_clock"],
          "cast": {"agent": {"group": "support", "not_group": "support-supervisors"}},
          "steps": [{"id": "s1", "actor": "agent", "op": "delegate", "agent": "support-orchestrator", "role": "support-agent", "task": "ticket-{n}", "ttl": 60, "save": "t", "expect": "ok"},
                    {"id": "s2", "actor": "support-orchestrator", "op": "call", "token": "t", "action": "read", "resource": "crm.ticket/t-{n}",
                     "attrs": {"region": "{agent.region}"}, "expect": "allow"},
                    {"id": "s3", "actor": "clock", "op": "advance", "seconds": 61},
                    {"id": "s4", "actor": "support-orchestrator", "op": "call", "token": "t", "action": "read", "resource": "crm.ticket/t-{n}",
                     "attrs": {"region": "{agent.region}"}, "expect": "deny:token_expired"}]}


class Wrong(InProcess):
    """The real engine, with one kind of answer changed."""

    def __init__(self, change):
        super().__init__()
        self.change = change

    def call(self, op, payload):
        return self.change(op, payload, super().call(op, payload))


def allow_instead_of(*reasons):
    def change(op, payload, resp):
        if op in ("authorize", "filter") and resp.get("ok") and resp.get("reason") in reasons:
            return dict(resp, effect="allow", reason="permitted", data=payload.get("data"))
        return resp
    return change


def run(backend=None, wanted="all", scenarios=None, instances=None):
    backend = backend or InProcess()
    try:
        r = Run(backend, Company(), scenarios or load_scenarios())
        r.run(wanted, instances)
    finally:
        backend.close()
    return r


def kinds(r):
    return {v["invariant"] for v in r.violations}


def main(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(list(argv))
    return code, out.getvalue()


class CompanyBundle(unittest.TestCase):
    def test_it_loads_and_its_policy_tests_pass(self):
        p = subprocess.run([sys.executable, "-m", "sf_smartdelegate", "policy", "test", "--bundle", str(COMPANY)], capture_output=True, text=True, env=ENV, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        n = sum(len(json.loads(f.read_text(encoding="utf-8"))["cases"]) for f in (COMPANY / "tests").glob("*.json"))
        self.assertGreaterEqual(n, 60)

    def test_compiled_policies_are_what_the_engine_loads(self):
        c = Company()
        self.assertGreaterEqual(len(c.users), 30)
        self.assertGreaterEqual(len(c.roles), 12)
        b = InProcess()
        try:
            info = b.call("info", {})
        finally:
            b.close()
        self.assertTrue(info["ok"])
        self.assertEqual(len(info["policy_version"]), 64)


class Scenarios(unittest.TestCase):
    def test_each_is_described(self):
        docs = load_scenarios()
        self.assertGreaterEqual(len(docs), 5)
        for doc in docs.values():
            self.assertTrue(all(s.get("why") for s in doc["steps"] if s.get("expect")), doc["id"])

    def test_every_scenario_passes_in_process(self):
        r = run(instances=12)
        self.assertEqual((r.violations, r.harness_errors, r.skipped), ([], [], {}))
        self.assertEqual(len(r.instances), 12)
        self.assertEqual(r.audit["decisions_matched"], sum(1 for e in r.trace if e["op"] in ("authorize", "filter") and e["response"].get("ok") and not e["request"].get("dry_run")))

    def test_every_scenario_passes_through_the_daemon(self):
        with Daemon({"bundle_dir": str(COMPANY)}) as d:
            os.environ["HARNESS_TEST_ADMIN"], os.environ["HARNESS_TEST_PEP"] = d.ADMIN, d.PEP
            try:
                code, out = main("run", "--backend", "url:" + d.url, "--admin-key-env", "HARNESS_TEST_ADMIN", "--pep-key-env", "HARNESS_TEST_PEP", "--out", self.tmp())
            finally:
                del os.environ["HARNESS_TEST_ADMIN"], os.environ["HARNESS_TEST_PEP"]
        self.assertEqual(code, 0, out)
        self.assertIn("verdict: PASS", out)
        self.assertNotIn("SKIP", out)

    def tmp(self):
        d = tempfile.mkdtemp(prefix="smartdelegate-harness-test-")
        self.addCleanup(shutil.rmtree, d, True)
        return d


class Checks(unittest.TestCase):
    def test_inv_j_a_wrong_expectation(self):
        docs = load_scenarios()
        step = next(s for s in docs["01_refund_escalation"]["steps"] if s.get("expect") == "deny:budget_exceeded")
        step["expect"] = "allow"
        r = run(wanted="01", scenarios=docs)
        self.assertEqual(kinds(r), {"INV-J"})
        self.assertIn("expected allow, got deny:budget_exceeded", r.violations[0]["detail"])

    def test_inv_b_a_denied_field_in_the_data(self):
        def change(op, payload, resp):
            return dict(resp, data=payload["data"]) if op == "filter" and resp.get("effect") == "allow" else resp
        self.assertIn("INV-B", kinds(run(Wrong(change))))

    def test_inv_c_spend_over_the_budget(self):
        self.assertIn("INV-C", kinds(run(Wrong(allow_instead_of("budget_exceeded")), wanted="01,11")))

    def test_inv_d_a_revoked_token_that_works(self):
        self.assertIn("INV-D", kinds(run(Wrong(allow_instead_of("token_revoked")), wanted="07")))

    def test_inv_d_an_expired_token_that_works(self):
        ok = run(wanted="90", scenarios={EXPIRY["id"]: EXPIRY})
        self.assertEqual((ok.violations, ok.harness_errors), ([], []))
        r = run(Wrong(allow_instead_of("token_expired")), wanted="90", scenarios={EXPIRY["id"]: EXPIRY})
        self.assertEqual(kinds(r), {"INV-D", "INV-J", "INV-I"})      # INV-I: the audit record still says deny

    def test_inv_i_a_decision_without_an_audit_record(self):
        def change(op, payload, resp):
            return dict(resp, records=resp["records"][:-3]) if op == "audit_tail" else resp
        self.assertEqual(kinds(run(Wrong(change), wanted="01")), {"INV-I"})

    def test_inv_i_an_audit_log_that_does_not_verify(self):
        def change(op, payload, resp):
            return {"ok": False, "error": {"code": "audit_corrupt", "message": "record 3: hash mismatch"}} if op == "audit_verify" else resp
        self.assertEqual(kinds(run(Wrong(change), wanted="01")), {"INV-I"})

    def test_no_answer_is_never_an_allow(self):
        def change(op, payload, resp):
            return {"ok": False, "error": {"code": "harness_transport", "message": "no answer"}} if op == "authorize" else resp
        r = run(Wrong(change), wanted="01")
        self.assertEqual(report.build(r, {})["verdict"], "ERROR")


class ReportsAndCommandLine(unittest.TestCase):
    def tmp(self):
        d = tempfile.mkdtemp(prefix="smartdelegate-harness-test-")
        self.addCleanup(shutil.rmtree, d, True)
        return d

    def test_reports_are_written_and_hold_no_token(self):
        out = self.tmp()
        code, text = main("run", "--out", out)
        self.assertEqual(code, 0, text)
        self.assertIn("verdict: PASS", text)
        doc = json.loads(Path(out, "report.json").read_text(encoding="utf-8"))
        for key in ("schema", "verdict", "exit_code", "config", "backend", "company", "totals", "scenarios", "rules", "invariants", "violations", "audit", "swimlanes", "trace"):
            self.assertIn(key, doc)
        self.assertEqual(sorted(doc["invariants"]), ["INV-B", "INV-C", "INV-D", "INV-I", "INV-J"])
        self.assertEqual(len(doc["scenarios"]), len(load_scenarios()))
        html = Path(out, "report.html").read_text(encoding="utf-8")
        self.assertIn("table class=lanes", html.replace('"', ""))
        self.assertNotIn("http://", html.replace("http://www.w3.org", ""))      # self-contained
        for text in (json.dumps(doc), html):
            self.assertNotRegex(text, r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")

    def test_list_and_run_py(self):
        code, text = main("list")
        self.assertEqual(code, 0)
        self.assertIn(f"{len(load_scenarios())} scenarios", text)
        p = subprocess.run([sys.executable, str(ROOT / "harness" / "run.py"), "list", "-v"], capture_output=True, text=True, env=ENV, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("01_refund_escalation", p.stdout)

    def test_exit_status_1_when_a_check_fails(self):
        d = self.tmp()
        doc = json.loads((SCENARIOS / "11_budget_tree.json").read_text(encoding="utf-8"))
        next(s for s in doc["steps"] if s.get("expect") == "deny:budget_exceeded")["expect"] = "allow"
        Path(d, "11_budget_tree.json").write_text(json.dumps(doc), encoding="utf-8")
        code, text = main("run", "--scenario-dir", d, "--out", self.tmp())
        self.assertEqual(code, 1, text)
        self.assertIn("VIOLATION INV-J", text)
        self.assertIn("verdict: FAIL", text)

    def test_exit_status_2_when_the_harness_cannot_run(self):
        self.assertEqual(main("run", "--scenarios", "99")[0], 2)
        self.assertEqual(main("run", "--backend", "rust")[0], 2)
        self.assertEqual(main("run", "--backend", "url:http://127.0.0.1:1")[0], 2)
        self.assertEqual(main("run", "--scenario-dir", self.tmp())[0], 2)

    def test_nothing_is_written_into_the_repository(self):
        code, text = main("run")           # no --out: the reports go to a new temporary directory
        where = Path(text.split("for machines")[1].strip()).parent
        self.addCleanup(shutil.rmtree, where, True)
        self.assertEqual(code, 0, text)
        self.assertTrue((where / "report.html").exists())
        self.assertNotIn(str(ROOT), str(where))
        self.assertFalse((ROOT / "harness" / "out").exists())
        self.assertFalse(list((ROOT / "harness").glob("report.[jh]*")))


if __name__ == "__main__":
    unittest.main()
