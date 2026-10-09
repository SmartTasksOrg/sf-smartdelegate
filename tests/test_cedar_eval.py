"""The policy evaluator against answers recorded from the real Cedar engine."""
import json
import unittest
from pathlib import Path

from support import SPEC

from sf_smartdelegate import cedar


class EvalVectors(unittest.TestCase):
    def test_every_case_matches_real_cedar(self):
        doc = json.loads((SPEC / "conformance" / "eval" / "cases.json").read_text(encoding="utf-8"))
        store = cedar.Store(doc["entities"])
        self.assertGreaterEqual(len(doc["cases"]), 60)
        for c in doc["cases"]:
            with self.subTest(c["name"]):
                if c["expect"].get("load_error"):
                    with self.assertRaises(cedar.Unsupported):
                        {pid: cedar.Policy(pid, est) for pid, est in c["policies"].items()}
                    continue
                policies = {pid: cedar.Policy(pid, est) for pid, est in c["policies"].items()}
                r = c["request"]
                env = cedar.Env(cedar.Entity(*r["principal"]), cedar.Entity("Action", r["action"]), cedar.Entity(*r["resource"]), cedar.from_json(r["context"]), store)
                got = cedar.is_authorized(policies, env)
                self.assertEqual({"decision": got["decision"], "reasons": got["reasons"], "errors": sorted(e[0] for e in got["errors"])}, c["expect"])


if __name__ == "__main__":
    unittest.main()
