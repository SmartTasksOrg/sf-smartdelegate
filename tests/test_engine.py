"""Engine behaviour beyond the shared vectors: shadow mode, signed bundles,
OIDC-backed issuance, audit tampering, verify-only engines, shared state."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import BUNDLE, CLI, ENV, FULL_CAP, OIDC, T, conformance_config

from sf_smartdelegate import SmartDelegateError, Engine
from sf_smartdelegate.errors import EngineError


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="smartdelegate-t-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def engine(self, **extra):
        cfg = conformance_config(os.path.join(self.dir, extra.pop("state", "state")))
        cfg.update(extra)
        e = Engine(cfg)
        self.addCleanup(e.close)
        return e

    def token(self, e, user="alice", cap=None, **kw):
        return e.issue_token("support-bot", cap or FULL_CAP, user=user, **kw)


class ShadowMode(Base):
    def test_shadow_allows_but_reports_and_logs(self):
        e = self.engine(mode="shadow")
        t = self.token(e)["token"]
        d = e.authorize(t, "delete", "crm.customer", "c-1")
        self.assertEqual(d["effect"], "allow")
        self.assertTrue(d["shadow"])
        self.assertEqual(d["would_deny"]["reason"], "capability_action")
        rec = e.call("audit_tail", {"n": 1})["records"][0]
        self.assertEqual((rec["effect"], rec["enforced"]), ("deny", False))

    def test_shadow_never_changes_data(self):
        e = self.engine(mode="shadow")
        t = self.token(e)["token"]
        data = {"id": "c-1", "ssn": "123-45-6789", "region": "EU"}
        d = e.filter(t, "read", "crm.customer", data, "c-1")
        self.assertEqual(d["data"], data)
        self.assertEqual(d["would_mask"], ["ssn"])

    def test_bad_token_in_shadow_is_still_reported(self):
        e = self.engine(mode="shadow")
        d = e.authorize("not.a.token", "read", "crm.customer", "c-1")
        self.assertEqual((d["effect"], d["would_deny"]["reason"]), ("allow", "token_invalid"))


class SignedBundles(Base):
    def setUp(self):
        super().setUp()
        self.bundle = os.path.join(self.dir, "bundle")
        shutil.copytree(BUNDLE, self.bundle)
        prefix = os.path.join(self.dir, "signer")
        subprocess.run([*CLI, "bundle", "keygen", prefix], check=True, capture_output=True, env=ENV)
        self.pub = Path(prefix + ".pub").read_text()
        self.key = prefix + ".key"

    def sign(self):
        subprocess.run([*CLI, "bundle", "sign", "--key", self.key, "--bundle", self.bundle], check=True, capture_output=True, env=ENV)

    def load(self, pub=None):
        e = Engine({"bundle_dir": self.bundle, "bundle_public_key": pub or self.pub})
        e.close()

    def test_unsigned_bundle_is_refused(self):
        with self.assertRaises(SmartDelegateError) as cm:
            self.load()
        self.assertEqual(cm.exception.code, "bundle_unsigned")

    def test_signed_bundle_loads_and_tampering_is_caught(self):
        self.sign()
        self.load()
        p = Path(self.bundle) / "policies.json"
        doc = json.loads(p.read_text())
        doc["policies"]["backdoor"] = {"effect": "permit", "principal": {"op": "All"}, "action": {"op": "All"}, "resource": {"op": "All"}, "conditions": []}
        p.write_text(json.dumps(doc))
        with self.assertRaises(SmartDelegateError) as cm:
            self.load()
        self.assertEqual(cm.exception.code, "bundle_signature")

    def test_changed_entities_are_caught(self):
        self.sign()
        p = Path(self.bundle) / "entities.json"
        p.write_text(p.read_text().replace('"id": "dave"}, "attrs": {"region": "US"}, "parents": []', '"id": "dave"}, "attrs": {"region": "US"}, "parents": [{"type": "Group", "id": "compliance"}]'))
        with self.assertRaises(SmartDelegateError) as cm:
            self.load()
        self.assertEqual(cm.exception.code, "bundle_signature")

    def test_wrong_key_is_refused(self):
        self.sign()
        other = os.path.join(self.dir, "other")
        subprocess.run([*CLI, "bundle", "keygen", other], check=True, capture_output=True, env=ENV)
        with self.assertRaises(SmartDelegateError) as cm:
            self.load(Path(other + ".pub").read_text())
        self.assertEqual(cm.exception.code, "bundle_signature")

    def test_source_edited_without_recompiling_is_refused(self):
        p = Path(self.bundle) / "policies" / "crm.cedar"
        p.write_text(p.read_text() + "\npermit(principal, action, resource);\n")
        with self.assertRaises(SmartDelegateError) as cm:
            Engine({"bundle_dir": self.bundle})
        self.assertEqual(cm.exception.code, "bundle_stale")
        (Path(self.bundle) / "policies" / "zz_new.cedar").write_text("permit(principal, action, resource);")
        with self.assertRaises(SmartDelegateError):
            Engine({"bundle_dir": self.bundle})

    def test_cedar_outside_the_subset_is_refused_at_load(self):
        p = Path(self.bundle) / "policies.json"
        doc = json.loads(p.read_text())
        doc["policies"]["uses-ip"] = {"effect": "forbid", "principal": {"op": "All"}, "action": {"op": "All"}, "resource": {"op": "All"},
                                      "conditions": [{"kind": "when", "body": {"isLoopback": [{"ip": [{"Value": "10.0.0.1"}]}]}}]}
        p.write_text(json.dumps(doc))
        with self.assertRaises(SmartDelegateError) as cm:
            Engine({"bundle_dir": self.bundle})
        self.assertEqual(cm.exception.code, "policy_parse")

    def test_failed_reload_keeps_the_old_bundle(self):
        e = Engine({"bundle_dir": self.bundle, "allow_test_clock": True})
        self.addCleanup(e.close)
        before = e.info()["policy_version"]
        good = (Path(self.bundle) / "policies.json").read_text()
        (Path(self.bundle) / "policies.json").write_text(good[:-40])
        self.assertEqual(e.call("reload", {})["error"]["code"], "policy_parse")
        self.assertEqual(e.info()["policy_version"], before)
        t = e.issue_token("support-bot", FULL_CAP, user="alice")["token"]
        self.assertEqual(e.authorize(t, "read", "crm.customer", "c-1")["effect"], "allow")

    def test_example_bundle_in_the_package_matches_the_spec(self):
        import sf_smartdelegate
        from sf_smartdelegate import bundle as b
        shipped = Path(sf_smartdelegate.__file__).parent / "example_bundle"
        self.assertEqual(b.version_of(b.manifest(shipped)), b.version_of(b.manifest(BUNDLE)))


class Oidc(Base):
    IDP = {"issuer": "https://idp.example.test", "audience": "smartdelegate-demo", "jwks_file": str(OIDC / "jwks.json")}

    def setUp(self):
        super().setUp()
        self.tokens = json.loads((OIDC / "id_tokens.json").read_text())

    def test_id_token_names_the_user(self):
        e = self.engine(idp=self.IDP)
        r = e.issue_token("support-bot", FULL_CAP, id_token=self.tokens["alice"])
        self.assertEqual(r["user"], "alice")
        self.assertEqual(e.authorize(r["token"], "read", "crm.customer", "c-1")["principal"]["user"], "alice")

    def test_id_token_cannot_be_used_for_someone_else(self):
        e = self.engine(idp=self.IDP)
        with self.assertRaises(SmartDelegateError) as cm:
            e.issue_token("support-bot", FULL_CAP, id_token=self.tokens["alice"], user="carol")
        self.assertEqual(cm.exception.code, "id_token_invalid")

    def test_policy_still_applies_to_a_verified_user(self):
        e = self.engine(idp=self.IDP)
        with self.assertRaises(SmartDelegateError) as cm:
            e.issue_token("support-bot", FULL_CAP, id_token=self.tokens["dave"])
        self.assertEqual(cm.exception.code, "delegation_denied")

    def test_bad_id_tokens_are_rejected(self):
        e = self.engine(idp=self.IDP)
        for name in ("expired", "wrong_audience", "wrong_issuer", "forged"):
            with self.assertRaises(SmartDelegateError, msg=name) as cm:
                e.issue_token("support-bot", FULL_CAP, id_token=self.tokens[name])
            self.assertEqual(cm.exception.code, "id_token_invalid", name)
        tampered = self.tokens["alice"][:-6] + "AAAAAA"
        with self.assertRaises(SmartDelegateError):
            e.issue_token("support-bot", FULL_CAP, id_token=tampered)

    def test_without_an_idp_id_tokens_are_refused(self):
        e = self.engine()
        with self.assertRaises(SmartDelegateError) as cm:
            e.issue_token("support-bot", FULL_CAP, id_token=self.tokens["alice"])
        self.assertEqual(cm.exception.code, "no_idp")


class Audit(Base):
    def log(self):
        return Path(self.dir) / "state" / "audit.jsonl"

    def fill(self):
        e = self.engine()
        t = self.token(e)["token"]
        for i in range(5):
            e.authorize(t, "read", "crm.customer", f"c-{i}")
        return e

    def test_chain_verifies(self):
        e = self.fill()
        self.assertEqual(e.call("audit_verify", {})["records"], 6)

    def test_edit_delete_and_reorder_are_detected(self):
        e = self.fill()
        original = self.log().read_text().splitlines()
        edited = list(original)
        edited[2] = edited[2].replace('"effect":"allow"', '"effect":"deny"')
        self.assertNotEqual(edited[2], original[2])
        for name, lines in (("edit", edited), ("delete", original[:2] + original[3:]), ("reorder", original[:2] + [original[3], original[2]] + original[4:])):
            self.log().write_text("\n".join(lines) + "\n")
            r = e.call("audit_verify", {})
            self.assertEqual(r.get("error", {}).get("code"), "audit_broken", name)

    def test_log_holds_field_names_not_values(self):
        e = self.engine()
        t = self.token(e)["token"]
        e.filter(t, "read", "crm.customer", {"id": "c-1", "ssn": "123-45-6789", "email": "ada@example.com", "region": "EU"}, "c-1")
        text = self.log().read_text()
        self.assertIn('"masked":["ssn"]', text)
        self.assertNotIn("123-45-6789", text)
        self.assertNotIn("ada@example.com", text)
        self.assertNotIn(t, text)

    def test_denials_on_revoked_tokens_are_attributed(self):
        e = self.engine()
        r = self.token(e)
        e.revoke(r["token_id"])
        d = e.authorize(r["token"], "read", "crm.customer", "c-1")
        self.assertEqual((d["effect"], d["reason"], d["principal"]["user"]), ("deny", "token_revoked", "alice"))
        rec = e.call("audit_tail", {"n": 1})["records"][0]
        self.assertEqual((rec["user"], rec["chain"], rec["effect"]), ("alice", ["support-bot"], "deny"))
        forged = e.authorize("abc.def.ghi", "read", "crm.customer", "c-1")
        self.assertIsNone(forged["principal"])

    def test_reopened_log_continues_the_chain(self):
        e = self.fill()
        e.close()
        e2 = self.engine()
        e2.authorize("x", "read", "crm.customer", "c-1")
        self.assertEqual(e2.call("audit_verify", {})["records"], 7)

    def test_engine_refuses_to_start_on_a_broken_log(self):
        e = self.fill()
        e.close()
        lines = self.log().read_text().splitlines()
        self.log().write_text("\n".join(lines[1:]) + "\n")
        with self.assertRaises(SmartDelegateError) as cm:
            Engine(conformance_config(os.path.join(self.dir, "state")))
        self.assertEqual(cm.exception.code, "audit_broken")


class Keys(Base):
    def test_verify_only_engine_checks_but_cannot_issue(self):
        issuer = self.engine()
        t = self.token(issuer)["token"]
        pub = issuer.info()["public_key"]
        verifier = self.engine(state="state2", verify_only=True, trusted_keys=[pub])
        self.assertEqual(verifier.authorize(t, "read", "crm.customer", "c-1")["effect"], "allow")
        with self.assertRaises(SmartDelegateError) as cm:
            verifier.issue_token("support-bot", FULL_CAP, user="alice")
        self.assertEqual(cm.exception.code, "no_signing_key")

    def test_token_from_an_unknown_issuer_key_is_denied(self):
        a = self.engine()
        b = self.engine(state="state2")
        t = self.token(a)["token"]
        self.assertEqual(b.authorize(t, "read", "crm.customer", "c-1")["reason"], "token_invalid")

    def test_token_for_another_issuer_name_is_denied(self):
        a = self.engine()
        t = self.token(a)["token"]
        pub = a.info()["public_key"]
        b = self.engine(state="state2", verify_only=True, trusted_keys=[pub], issuer="smartdelegate://other")
        self.assertEqual(b.authorize(t, "read", "crm.customer", "c-1")["reason"], "token_invalid")

    def test_altered_token_payload_is_denied(self):
        import base64
        e = self.engine()
        t = self.token(e, cap={"actions": ["read"], "resources": ["crm.customer/c-1"]})["token"]
        head, body, sig = t.split(".")
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        claims["cap"]["actions"] = ["*"]
        forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        self.assertEqual(e.authorize(f"{head}.{forged}.{sig}", "update", "crm.customer", "c-1")["reason"], "token_invalid")
        none_head = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        self.assertEqual(e.authorize(f"{none_head}.{forged}.", "update", "crm.customer", "c-1")["reason"], "token_invalid")

    def test_test_clock_is_ignored_unless_enabled(self):
        e = Engine({"bundle_dir": str(BUNDLE)})
        self.addCleanup(e.close)
        t = e.issue_token("support-bot", FULL_CAP, user="alice", ttl=60)["token"]
        d = e.call("authorize", {"token": t, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}, "now": T + 10**9})
        self.assertEqual(d["effect"], "allow")

    def test_caller_chain_is_only_trusted_when_configured(self):
        req = {"chain": {"user": "alice", "agents": ["support-bot"]}, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}}
        self.assertEqual(self.engine().call("authorize", req)["reason"], "token_invalid")
        self.assertEqual(self.engine(state="s2", trust_caller_chain=True).call("authorize", req)["effect"], "allow")


class SharedState(Base):
    def test_revocation_by_one_process_is_seen_by_another(self):
        a = self.engine()
        r = self.token(a)
        pub = a.info()["public_key"]
        b = self.engine(verify_only=True, trusted_keys=[pub])  # same state directory
        self.assertEqual(b.authorize(r["token"], "read", "crm.customer", "c-1")["effect"], "allow")
        a.revoke(r["token_id"])
        self.assertEqual(b.authorize(r["token"], "read", "crm.customer", "c-1")["reason"], "token_revoked")

    def test_two_processes_write_one_valid_audit_chain(self):
        a = self.engine()
        r = self.token(a)
        b = self.engine(verify_only=True, trusted_keys=[a.info()["public_key"]])
        for i in range(6):
            (a if i % 2 else b).authorize(r["token"], "read", "crm.customer", f"c-{i}")
        self.assertEqual(a.call("audit_verify", {})["records"], 7)
        self.assertEqual(b.call("audit_verify", {})["records"], 7)

    def test_spend_is_shared_between_processes(self):
        a = self.engine()
        r = self.token(a, cap={**FULL_CAP, "budget": {"EUR": 1000}})
        b = self.engine(verify_only=True, trusted_keys=[a.info()["public_key"]])
        spend = {"spend": {"currency": "EUR", "amount": 600}}
        self.assertEqual(a.authorize(r["token"], "create", "billing.refund", "r-1", context=spend)["effect"], "allow")
        self.assertEqual(b.authorize(r["token"], "create", "billing.refund", "r-2", context=spend)["reason"], "budget_exceeded")

    def test_unwritable_audit_log_fails_closed(self):
        e = self.engine()
        t = self.token(e)["token"]
        log = Path(self.dir) / "state" / "audit.jsonl"
        log.unlink()
        log.mkdir()
        out = e.call("authorize", {"token": t, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}})
        self.assertEqual(out.get("error", {}).get("code"), "audit_io")
        self.assertNotIn("effect", out)

    def test_corrupt_state_file_fails_closed(self):
        e = self.engine()
        r = self.token(e)
        e.revoke(r["token_id"])
        (Path(self.dir) / "state" / "state.json").write_text("{not json")
        out = e.call("authorize", {"token": r["token"], "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}})
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"]["code"], "state_io")


if __name__ == "__main__":
    unittest.main()
