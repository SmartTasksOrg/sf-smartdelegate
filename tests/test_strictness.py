"""The "Strictness (0.3)" rules of spec/PORTING.md, which the shared vectors
cannot express (they need a mutated token or a damaged file). Every port has
the same checks in its own test suite."""
import json
import multiprocessing
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from support import BUNDLE, FULL_CAP, T

from sf_smartdelegate import Engine
from sf_smartdelegate import cedar, tokens
from sf_smartdelegate.errors import EngineError


def _start(state):
    with Engine({"bundle_dir": str(BUNDLE), "state_dir": state}) as e:
        return e.call("info", {})["key_id"]


class Strictness(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="smartdelegate-strict-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def engine(self, **extra):
        e = Engine({"bundle_dir": str(BUNDLE), "state_dir": os.path.join(self.dir, "state"), "allow_test_clock": True, **extra})
        self.addCleanup(e.close)
        return e

    def token(self, e):
        return e.call("issue_token", {"user": "alice", "agent": "support-bot", "cap": FULL_CAP, "now": T})["token"]

    def test_audit_lines_end_at_newline_only(self):
        e = self.engine()
        odd = "x y z\u0085w"
        self.assertTrue(e.call("revoke", {"token_id": odd, "now": T})["ok"])
        tail = e.call("audit_tail", {"n": 5})["records"]
        self.assertEqual(tail[-1]["token_id"], odd)
        other = Engine({"bundle_dir": str(BUNDLE), "state_dir": os.path.join(self.dir, "state"), "allow_test_clock": True})
        self.addCleanup(other.close)
        self.assertTrue(other.call("revoke", {"token_id": "second", "now": T})["ok"])
        self.assertEqual(e.call("audit_verify", {})["records"], 2)

    def test_base64url_is_strict(self):
        e = self.engine()
        t = self.token(e)
        h, b, s = t.split(".")
        for bad in (t + "!!!!", f"{h}.{b}.{s[:10]}!!!!{s[10:]}", f"{h}.{b[:8]} {b[8:]}.{s}", f"{h}=.{b}.{s}", f"{h}.{b}.{s}=",
                    f"{h}\n.{b}.{s}", t.replace("-", "+").replace("_", "/") if ("-" in t or "_" in t) else t + "+"):
            r = e.call("authorize", {"token": bad, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}, "now": T})
            self.assertEqual((r["effect"], r["reason"]), ("deny", "token_invalid"), bad[-30:])
            self.assertEqual(e.call("inspect_token", {"token": bad, "now": T})["valid"], False)

    def test_entity_type_names_match_in_full(self):
        self.assertTrue(cedar.valid_type("Ns::User"))
        for bad in ("User\n", "User ", "1User", "User::", "", "Us er"):
            self.assertFalse(cedar.valid_type(bad), repr(bad))

    def test_policy_shapes_are_checked_at_load(self):
        ok = {"effect": "permit", "principal": {"op": "All"}, "action": {"op": "All"}, "resource": {"op": "All"}, "conditions": []}
        cedar.Policy("ok", ok)
        for change in ({"conditions": {}}, {"conditions": ""}, {"conditions": None}, {"annotations": ["id"]}, {"annotations": "id"},
                       {"annotations": 7}, {"action": {"op": "in", "entities": {}}},
                       {"conditions": [{"kind": "when", "body": {"Set": {}}}]},
                       {"conditions": [{"kind": "when", "body": {"Record": []}}]},
                       {"conditions": [{"kind": "when", "body": {"like": {"left": {"Value": "a"}, "pattern": "a"}}}]}):
            with self.assertRaises(cedar.Unsupported, msg=str(change)):
                cedar.Policy("bad", {**ok, **change})

    def test_anc_must_be_an_array_of_strings(self):
        e = self.engine()
        claims = tokens.Keys(Path(self.dir, "state", "signing_key.pk8.b64").read_text(), []).verify(self.token(e), e.issuer)
        for anc in ("abc", {"a": 1}, [1], 7):
            forged = e.keys.sign({**claims, "anc": anc})
            self.assertEqual(e.call("inspect_token", {"token": forged, "now": T}).get("reason"), "token_invalid", repr(anc))

    def test_files_that_are_not_utf8(self):
        e = self.engine()
        self.token(e)
        state = Path(self.dir, "state")
        (state / "state.json").write_bytes(b'{"revoked": "\xff\xfe"}')
        self.assertEqual(e.call("info", {})["error"]["code"], "state_io")
        (state / "state.json").unlink()
        (state / "audit.jsonl").write_bytes(b"\xff\xfe\n")
        self.assertEqual(e.call("audit_verify", {})["error"]["code"], "audit_broken")
        b = Path(self.dir, "bundle")
        shutil.copytree(BUNDLE, b)
        (b / "catalog.json").write_bytes(b"\xff\xfe{}")
        with self.assertRaises(EngineError) as cm:
            Engine({"bundle_dir": str(b)})
        self.assertEqual(cm.exception.code, "bundle_io")

    def test_entities_must_be_a_list_of_objects(self):
        for n, doc in enumerate(("{}", "null", "0", "[1]", '["x"]', '[{"uid": 5}]')):
            b = Path(self.dir, f"bundle{n}")
            shutil.copytree(BUNDLE, b)
            (b / "entities.json").write_text(doc)
            with self.assertRaises(EngineError) as cm:
                Engine({"bundle_dir": str(b)})
            self.assertEqual(cm.exception.code, "entities_parse", doc)

    def test_racing_to_create_the_signing_key(self):
        for round_ in range(3):
            state = os.path.join(self.dir, f"race{round_}")
            with multiprocessing.get_context("spawn").Pool(8) as pool:
                ids = pool.map(_start, [state] * 8)
            self.assertEqual(len(set(ids)), 1, ids)
            self.assertFalse([f for f in os.listdir(state) if f.endswith(".tmp")])


    def test_an_empty_key_file_is_not_no_key(self):
        import threading
        state = Path(self.dir, "late")
        state.mkdir()
        (state / "signing_key.pk8.b64").write_text("")
        from sf_smartdelegate import bundle
        private, _ = bundle.keygen()
        threading.Timer(0.4, lambda: (state / "signing_key.pk8.b64").write_text(private)).start()
        with Engine({"bundle_dir": str(BUNDLE), "state_dir": str(state)}) as e:
            info = e.call("info", {})
        self.assertTrue(info["can_issue"])
        self.assertTrue(info["key_id"])


    def test_a_verifier_with_its_own_state_enforces_an_ancestors_budget(self):
        issuer = self.engine()
        ref = {"path": "billing.refund", "id": "r"}
        parent = issuer.call("issue_token", {"user": "alice", "agent": "support-bot", "now": T, "cap": {
            "actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 10000}}})
        kids = [issuer.call("exchange_token", {"subject_token": parent["token"], "actor": "refund-helper", "ttl": 300, "now": T,
                                               "cap": {"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 6000}}})
                for _ in range(3)]
        self.assertEqual(issuer.call("inspect_token", {"token": kids[0]["token"], "now": T})["claims"]["lim"],
                         {parent["token_id"]: {"EUR": 10000}})
        verifier = Engine({"bundle_dir": str(BUNDLE), "state_dir": os.path.join(self.dir, "verifier"), "allow_test_clock": True,
                           "verify_only": True, "trusted_keys": [issuer.call("info", {})["public_key"]]})
        self.addCleanup(verifier.close)
        spend = lambda k: verifier.call("authorize", {"token": k["token"], "action": "create", "resource": ref, "now": T,
                                                      "context": {"spend": {"currency": "EUR", "amount": 5000}}})
        self.assertEqual(spend(kids[0])["effect"], "allow")
        self.assertEqual(spend(kids[1])["effect"], "allow")
        third = spend(kids[2])
        self.assertEqual((third["effect"], third["reason"]), ("deny", "budget_exceeded"))
        # a forged or malformed lim is not a token
        claims = issuer.keys.verify(kids[0]["token"], issuer.issuer)
        for bad in ("x", [], {"a": 5}, {"a": {"EUR": -1}}, {"a": {"EUR": "9"}}):
            self.assertEqual(issuer.call("inspect_token", {"token": issuer.keys.sign({**claims, "lim": bad}), "now": T}).get("reason"),
                             "token_invalid", repr(bad))


if __name__ == "__main__":
    unittest.main()
