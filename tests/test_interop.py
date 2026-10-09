"""Ports must agree on the formats they share: tokens, keys, signed bundles,
the state file and the audit chain. These tests run the Python reference
against the Rust port when its binary has been built (ports/rust), and are
skipped otherwise."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import BUNDLE, CLI, ENV, FULL_CAP, ROOT, conformance_config

from sf_smartdelegate import Engine

EXE = ".exe" if os.name == "nt" else ""
RUST = Path(os.environ.get("SMARTDELEGATE_RUST_BIN") or ROOT / "ports" / "rust" / "target" / "release" / f"smartdelegate{EXE}")
REQ = ["authorize", "--action", "read", "--resource", "crm.customer/c-1"]


@unittest.skipUnless(RUST.exists(), "Rust port not built (cargo build --release in ports/rust)")
class PythonAndRust(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="smartdelegate-x-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.state = os.path.join(self.dir, "state")
        self.cfg = os.path.join(self.dir, "smartdelegate.json")
        Path(self.cfg).write_text(json.dumps(conformance_config(self.state)))
        self.cap = os.path.join(self.dir, "cap.json")
        Path(self.cap).write_text(json.dumps(FULL_CAP))

    def run_cli(self, cli, *args):
        r = subprocess.run([*cli, *args, "--config", self.cfg], capture_output=True, text=True, env=ENV)
        return r.returncode, r.stdout.strip(), r.stderr

    def rust(self, *args):
        return self.run_cli([str(RUST)], *args)

    def python(self, *args):
        return self.run_cli(CLI, *args)

    def test_both_ports_report_the_same_policy_version(self):
        a = json.loads(self.python("info")[1])["policy_version"]
        b = json.loads(self.rust("info")[1])["policy_version"]
        self.assertEqual(a, b)

    def test_token_issued_by_either_port_is_accepted_by_the_other(self):
        for issuer, verifier in ((self.python, self.rust), (self.rust, self.python)):
            shutil.rmtree(self.state, ignore_errors=True)     # a fresh signing key, written by the issuer's port
            code, token, err = issuer("token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "@" + self.cap, "--raw")
            self.assertEqual(code, 0, err)
            code, out, err = verifier(*REQ, "--token", token)
            self.assertEqual(code, 0, out + err)
            d = json.loads(out)
            self.assertEqual((d["effect"], d["principal"]["user"]), ("allow", "alice"))
            # and the other port can delegate from it and revoke it
            narrow = os.path.join(self.dir, "narrow.json")
            Path(narrow).write_text(json.dumps({"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["pii"]}))
            code, child, err = verifier("token", "exchange", "--token", token, "--actor", "refund-helper", "--cap", "@" + narrow, "--ttl", "300", "--raw")
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(issuer(*REQ, "--token", child)[1])["principal"]["chain"], ["support-bot", "refund-helper"])
            self.assertEqual(verifier("token", "revoke", "--token", token)[0], 0)
            self.assertEqual(json.loads(issuer(*REQ, "--token", child)[1])["reason"], "token_revoked")

    def test_both_ports_write_one_valid_audit_chain_and_share_spend(self):
        code, token, err = self.python("token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "@" + self.cap, "--raw")
        self.assertEqual(code, 0, err)
        spend = os.path.join(self.dir, "spend.json")
        Path(spend).write_text(json.dumps({"spend": {"currency": "EUR", "amount": 8000}}))
        refund = ["authorize", "--action", "create", "--resource", "billing.refund/r-1", "--context", "@" + spend, "--token", token]
        self.assertEqual(self.rust(*refund)[0], 0)
        self.assertEqual(self.python(*refund)[0], 0)
        self.assertEqual(json.loads(self.rust(*refund)[1])["reason"], "budget_exceeded")      # 3 x 8000 > 20000
        self.assertEqual(json.loads(self.python(*refund)[1])["reason"], "budget_exceeded")
        for port in (self.python, self.rust):
            code, out, err = port("audit", "verify")
            self.assertEqual(code, 0, out + err)
            self.assertEqual(json.loads(out)["records"], 5)

    def test_bundle_signed_by_either_port_verifies_in_the_other(self):
        for signer, loader in ((CLI, [str(RUST)]), ([str(RUST)], CLI)):
            b = os.path.join(self.dir, "bundle-" + ("py" if signer is CLI else "rs"))
            shutil.copytree(BUNDLE, b)
            prefix = os.path.join(self.dir, "k-" + ("py" if signer is CLI else "rs"))
            subprocess.run([*signer, "bundle", "keygen", prefix], check=True, capture_output=True, env=ENV)
            subprocess.run([*signer, "bundle", "sign", "--key", prefix + ".key", "--bundle", b], check=True, capture_output=True, env=ENV)
            cfg = os.path.join(self.dir, "signed.json")
            Path(cfg).write_text(json.dumps({"bundle_dir": b, "bundle_public_key": Path(prefix + ".pub").read_text()}))
            r = subprocess.run([*loader, "info", "--config", cfg], capture_output=True, text=True, env=ENV)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIsNotNone(json.loads(r.stdout)["bundle_signed_by"])
            p = Path(b) / "entities.json"
            p.write_text(p.read_text().replace('"region": "EU"', '"region": "US"', 1))
            r = subprocess.run([*loader, "info", "--config", cfg], capture_output=True, text=True, env=ENV)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("bundle_signature", r.stdout + r.stderr)

    def test_rust_port_passes_the_vectors_from_the_compiled_bundle(self):
        r = subprocess.run([str(RUST), "conformance", str(ROOT / "spec" / "conformance" / "vectors"), str(BUNDLE)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])


if __name__ == "__main__":
    unittest.main()
