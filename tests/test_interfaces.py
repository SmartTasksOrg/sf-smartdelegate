"""interfaces/: the adopter-facing contracts, their reference implementations
and the contract test kit.

    cd tests && python3 -m unittest test_interfaces -v

Every contract check is run twice: against the reference implementation (it
must pass) and against implementations that are broken on purpose (each must
be caught, by exactly the checks listed for it). `test_every_check_is_caught`
fails when a check exists that no broken implementation trips.

Standard library only; no network beyond one connection attempt to a closed
loopback port.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from support import BUNDLE, ENV, OIDC, ROOT

sys.path.insert(0, str(ROOT))

import interfaces  # noqa: E402
from interfaces import contract  # noqa: E402
from interfaces.contract import fake_scim, kit  # noqa: E402
from interfaces.contracts import (ApprovalRequest, DirectoryError, FeedError, Identity, IdentityError, Outcome, Refusal, Revocation,  # noqa: E402
                                  SinkError, SpawnRefused, Verdict)
from interfaces.reference import (FACTORIES, AdapterEnforcementPoint, ConsoleApprovalChannel, FileRevocationFeed, FileRoleCatalog,  # noqa: E402
                                  JsonlAuditSink, JwksIdentitySource, ScimDirectorySource, SimpleRuntime, WebhookApprovalChannel,
                                  apply_revocations, approval_webhook, pump, revocations_from_audit, ship, sync_directory)
from sf_smartdelegate import Engine  # noqa: E402
from sf_smartdelegate.backend import SmartDelegateError  # noqa: E402
from sf_smartdelegate.bridges.directory import Snapshot  # noqa: E402
from sf_smartdelegate.errors import rule_id  # noqa: E402

INTERFACES = sorted(kit.FACTORY_ARGUMENTS)


def failed(interface: str, factory) -> list:
    return sorted(r.id for r in contract.run(interface, factory) if not r.ok)


# ---- deliberately broken implementations --------------------------------------
# Each differs from the reference in one way. BROKEN maps
# interface -> {name: (factory, the checks that must catch it)}.

def _payload(token: str) -> dict:
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


class _Idp(JwksIdentitySource):
    """The reference with one verification step or one rule about groups removed."""
    flaw = ""
    memory: dict = {}

    def verify(self, id_token):
        if self.flaw == "no_signature":
            try:
                c = _payload(id_token)
            except Exception:
                raise IdentityError("id_token_invalid", "not a JWT") from None
            if c.get("iss") != self.issuer or c.get("aud") != self.audience or c.get("exp", 0) < 1700000000 or c.get("azp", self.audience) != self.audience:
                raise IdentityError("id_token_invalid", "claims")
            return c
        try:
            return super().verify(id_token)
        except IdentityError as e:
            skip = {"no_audience": "wrong audience", "no_issuer": "wrong issuer", "no_expiry": "expired", "no_azp": "azp"}.get(self.flaw)
            if skip and (skip in e.message or (self.flaw == "no_azp" and "several audiences" in e.message)):
                return _payload(id_token)
            raise

    def groups(self, claims):
        if self.flaw == "raw_groups":
            return sorted(claims.get("groups") or [])
        if self.flaw == "keeps_unmapped":
            return sorted(set(super().groups(claims)) | {g for g in claims.get("groups") or [] if isinstance(g, str) and g.startswith("sg-un")})
        try:
            got = super().groups(claims)
        except IdentityError:
            if self.flaw == "malformed_is_empty":
                return []
            raise
        if self.flaw == "none_for_no_groups":
            return got or None
        if self.flaw == "error_for_no_groups" and not got:
            raise IdentityError("no_groups", "the user has no groups")
        if self.flaw == "default_group":
            return got or ["support"]
        if self.flaw == "cached":
            if got:
                self.memory[claims["sub"]] = got
            return self.memory.get(claims["sub"], got)
        return got


def idp(flaw: str):
    def factory(issuer, audience, jwks, groups_claim, group_map):
        cls = type("Broken", (_Idp,), {"flaw": flaw, "memory": {}})
        return cls(issuer, audience, jwks, groups_claim=groups_claim, group_map=group_map)
    return factory


class _Directory:
    def __init__(self, fault, flaw):
        self.inner, self.fault, self.flaw = FACTORIES["directory"](fault), fault, flaw
        self.calls = 0

    def snapshot(self):
        _Directory.count = getattr(_Directory, "count", 0) + 1
        try:
            snap = self.inner.snapshot()
        except DirectoryError:
            if self.flaw == "swallows_errors" and self.fault == "unreachable":
                return Snapshot()
            if self.flaw == "partial" and self.fault == "truncated":
                snap = FACTORIES["directory"](None).snapshot()
                del snap.users["u-frank"], snap.memberships["u-frank"]
                return snap
            raise
        if self.flaw == "flat":
            for g in snap.groups.values():
                g.parents = set()
        if self.flaw == "all_active":
            for u in snap.users.values():
                u.active = True
        if self.flaw == "dangling":
            snap.memberships["u-dave"] = {"g-deleted-last-week"}
        if self.flaw == "flaky" and _Directory.count % 2:
            del snap.users["u-carol"], snap.memberships["u-carol"]
        return snap


def directory(flaw: str):
    return lambda fault=None: _Directory(fault, flaw)


class _Roles(FileRoleCatalog):
    flaw = ""

    def __init__(self, bundle_dir):
        super().__init__(bundle_dir)
        self.first = super().load()
        if self.flaw == "elsewhere":
            draft = self.path.with_name("roles.draft.json")
            if not draft.exists():
                shutil.copy(self.path, draft)
            self.path = draft

    def load(self):
        if self.flaw == "unwrapped":
            return super().load()["roles"]
        return self.first if self.flaw == "stale" else super().load()

    def validate(self, document):
        if self.flaw == "no_validation":
            return
        if self.flaw == "top_level_only":
            if not isinstance(document, dict) or set(document) != {"roles"} or not isinstance(document["roles"], dict):
                super().validate(document)
            return
        if self.flaw == "strips_unknown":
            document = self._strip(document)
        super().validate(document)

    @staticmethod
    def _strip(document):
        if not isinstance(document, dict) or not isinstance(document.get("roles"), dict):
            return document
        keep = {"description", "members", "cap", "max_ttl", "tasks", "agents", "bindings"}
        caps = {"actions", "resources", "deny_labels", "deny_fields", "budget"}
        out = {}
        for name, r in document["roles"].items():
            if isinstance(r, dict):
                r = {k: v for k, v in r.items() if k in keep}
                if isinstance(r.get("cap"), dict):
                    r["cap"] = {k: v for k, v in r["cap"].items() if k in caps}
            out[name] = r
        return {"roles": out}

    def write(self, document):
        if self.flaw == "strips_unknown":
            document = self._strip(document)
        if self.flaw == "no_validation":
            self.path.write_text(json.dumps(document), encoding="utf-8")
            return "0" * 64
        return super().write(document)


def roles(flaw: str):
    return lambda bundle_dir: type("Broken", (_Roles,), {"flaw": flaw})(bundle_dir)


class _Pep:
    """A hand-written enforcement point (authorize, run, filter) with one step left out."""

    def __init__(self, backend, tools, flaw):
        self.backend, self.tools, self.flaw = backend, tools, flaw
        self.last_good = ""

    def invoke(self, token, tool, arguments):
        if self.flaw == "caches_token":
            token = token or self.last_good
        binding, fn = self.tools[tool] if self.flaw == "unknown_tool_raises" else self.tools.get(tool, (None, None))
        if binding is None:
            return Outcome(False, None, Refusal("unknown_tool", rule_id("unknown_tool")))
        if self.flaw == "runs_first":
            result = fn(**arguments)
        context = None
        if binding.spend:
            amount = arguments.get(binding.spend[1])
            if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
                return Outcome(False, None, Refusal("invalid_arguments", rule_id("invalid_arguments")))
            context = {"spend": {"currency": arguments.get(binding.spend[0]), "amount": amount}}
        rid = arguments.get(binding.id) if binding.id else None
        data = arguments.get(binding.input) if binding.input and self.flaw != "not_strict" else None
        try:
            if data is not None:
                d = self.backend.filter(token or "", binding.action, binding.resource, data, rid, context=context, strict=True)
            else:
                d = self.backend.authorize(token or "", binding.action, binding.resource, rid, context=context,
                                           dry_run=True if self.flaw == "dry_run" else None)
        except SmartDelegateError as e:
            if self.flaw == "fail_open":
                return Outcome(True, fn(**arguments))
            return Outcome(False, None, Refusal(e.code, rule_id(e.code), e.message))
        if d["effect"] != "allow":
            approval = None if self.flaw == "drops_approval" else (d.get("approval") or {}).get("id")
            return Outcome(False, None, Refusal(d["reason"], d["rule"], d.get("detail", ""), approval, d.get("decision_id")))
        self.last_good = token
        if self.flaw != "runs_first":
            result = fn(**arguments)
        if self.flaw == "no_mask":
            return Outcome(True, result)
        if not isinstance(result, (dict, list)):
            return Outcome(True, result if self.flaw == "passes_text" else "[withheld]")
        return Outcome(True, self.backend.apply_obligations(d, result)["data"])


def pep(flaw: str):
    return lambda backend, tools: _Pep(backend, tools, flaw)


class _Runtime(SimpleRuntime):
    flaw = ""
    shared = [""]

    def begin_task(self, token):
        super().begin_task(token)
        self.shared[0] = token

    def end_task(self):
        if self.flaw != "keeps_token":
            super().end_task()
            self.shared[0] = ""

    def current_token(self):
        if self.flaw == "global_token":
            return self.shared[0]
        token = super().current_token()
        if not token and self.flaw == "service_account":
            return self.backend.issue_token("support-bot", user="alice", role="support-agent", task="fallback")["token"]
        return token

    def call(self, name, arguments):
        if self.flaw == "raises_on_unknown" and name not in self.enforcement.tools:
            raise KeyError(name)
        return super().call(name, arguments)

    def _child(self, token):
        child = type(self)(self.backend, self.enforcement)
        child.shared = [""]
        child.begin_task(token)
        return child

    def spawn(self, actor, capability=None, ttl=None):
        if self.flaw == "shares_token":
            return self._child(self.current_token())
        if self.flaw == "fresh_root":
            who = self.backend.inspect_token(self.current_token())
            return self._child(self.backend.issue_token("support-bot", capability, user=who["user"], role=who["claims"]["role"], task="sub")["token"])
        try:
            return self._child(super().spawn(actor, None if self.flaw == "ignores_capability" else capability, ttl).current_token())
        except SpawnRefused:
            if self.flaw == "falls_back":
                return self._child(self.current_token())
            raise


def runtime(flaw: str):
    return lambda backend: type("Broken", (_Runtime,), {"flaw": flaw, "shared": [""]})(backend)


class _Channel:
    def __init__(self, human, flaw):
        self.human, self.flaw, self.ready, self.seen = human, flaw, [], []

    def deliver(self, request: ApprovalRequest):
        self.seen.append(request.id)
        shown = {"approval_id": request.id} if self.flaw == "minimal_payload" else dict(request.__dict__, approval_id=request.id)
        reply = self.human(shown)
        if self.flaw == "auto_approve" and reply is None:
            reply = {"approve": True, "by": "bob"}
        if not isinstance(reply, dict) or "by" not in reply and self.flaw != "loose":
            return
        approve = reply.get("approve")
        if self.flaw == "loose":
            approve, reply = bool(approve), dict(reply, by=reply.get("by", "bob"))
        if self.flaw == "ignores_flag":
            approve = True
        if not isinstance(approve, bool):
            return
        by = {"fixed_approver": "bob", "service_account": "approvals-service"}.get(self.flaw, reply["by"])
        self.ready.append(Verdict(request.id, approve, by))

    def verdicts(self):
        out = list(self.ready)
        if self.flaw == "broadcast" and any(v.approve for v in out):
            out = [Verdict(i, True, out[0].by) for i in self.seen]
        if self.flaw != "never_drained":
            self.ready = []
        return out


def channel(flaw: str):
    return lambda human: _Channel(human, flaw)


class _Sink(JsonlAuditSink):
    flaw = ""
    memory: dict = {}

    def __init__(self, path):
        super().__init__(path)
        if self.flaw == "in_memory":
            self.memory[str(self.path)] = []

    def _held(self):
        return self.memory[str(self.path)] if self.flaw == "in_memory" else super()._held()

    def _store(self, records):
        if self.flaw == "in_memory":
            self.memory[str(self.path)].extend(records)
        else:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write("".join(kit.canon(r) + "\n" for r in records))

    def head(self):
        held = self._held()
        if self.flaw == "head_is_first":
            return (held[0]["seq"], held[0]["hash"]) if held else None
        return (held[-1]["seq"], held[-1]["hash"]) if held else None

    def append(self, records):
        from interfaces.reference.audit import check_append
        held = self._held()
        index = {r["seq"]: r["hash"] for r in held}
        last = max(index) if index else 0
        if self.flaw == "rejects_replay" and any(r["seq"] <= last for r in records):
            raise SinkError("duplicate", "already held")
        tolerated = {"accepts_gaps": "audit_gap", "no_chain_check": "audit_broken", "ignores_rewrite": "audit_rewritten"}.get(self.flaw)
        try:
            new = check_append((last, index[last]) if index else None, index.get, records)
        except SinkError as e:
            if e.code != tolerated:
                raise
            new = [r for r in records if r["seq"] > last]
        self._store(new)


def sink(flaw: str):
    return lambda location: type("Broken", (_Sink,), {"flaw": flaw, "memory": {}})(Path(location) / "copy.jsonl")


class _Feed(FileRevocationFeed):
    flaw = ""

    def __init__(self, path):
        super().__init__(path)
        self.mem: list = []

    def publish(self, events):
        if self.flaw == "tokens_only":
            events = [e for e in events if e.kind == "token"]
        if self.flaw == "drops_by":
            events = [Revocation(e.seq, e.kind, e.subject, e.ts, None) for e in events]
        if self.flaw == "in_memory":
            self.mem = sorted({e.seq: e for e in self.mem + list(events)}.values(), key=lambda e: e.seq)
            return
        if self.flaw in ("duplicates", "unordered"):
            have = set() if self.flaw == "duplicates" else {e.seq for e in self._read()}
            with open(self.path, "a", encoding="utf-8") as f:
                f.write("".join(json.dumps(e.to_json()) + "\n" for e in events if e.seq not in have))
            return
        super().publish(events)

    def poll(self, after=0):
        if self.flaw == "in_memory":
            return [e for e in self.mem if e.seq > after]
        if self.flaw in ("duplicates", "unordered"):
            return [e for e in self._read() if e.seq > after]
        if self.flaw == "ignores_after":
            return super().poll(0)
        return super().poll(after)


def feed(flaw: str):
    return lambda location: type("Broken", (_Feed,), {"flaw": flaw})(Path(location) / "feed.jsonl")


BROKEN = {
    "identity": {
        "does not check the signature": (idp("no_signature"), ["identity-forged"]),
        "does not check the audience": (idp("no_audience"), ["identity-wrong-audience"]),
        "does not check azp": (idp("no_azp"), ["identity-other-client"]),
        "does not check the issuer": (idp("no_issuer"), ["identity-wrong-issuer"]),
        "does not check expiry": (idp("no_expiry"), ["identity-expired"]),
        "returns the provider's group names unmapped": (idp("raw_groups"), ["identity-feeds-issuance", "identity-malformed-groups", "identity-no-stale-groups", "identity-unmapped-dropped", "identity-valid-token"]),
        "keeps groups that are not in the map": (idp("keeps_unmapped"), ["identity-unmapped-dropped"]),
        "reads a malformed groups claim as no groups": (idp("malformed_is_empty"), ["identity-malformed-groups"]),
        "returns None for a user with no groups": (idp("none_for_no_groups"), ["identity-feeds-issuance", "identity-no-groups-is-empty", "identity-no-stale-groups"]),
        "raises for a user with no groups": (idp("error_for_no_groups"), ["identity-feeds-issuance", "identity-no-groups-is-empty", "identity-no-stale-groups"]),
        "puts a user with no groups into a default group": (idp("default_group"), ["identity-feeds-issuance", "identity-no-groups-is-empty", "identity-no-stale-groups"]),
        "remembers a user's groups from an earlier token": (idp("cached"), ["identity-no-stale-groups"]),
    },
    "directory": {
        "drops group nesting": (directory("flat"), ["directory-entities-load", "directory-matches-fixture"]),
        "reports inactive users as active": (directory("all_active"), ["directory-entities-load", "directory-matches-fixture"]),
        "lists a membership in a group it did not list": (directory("dangling"), ["directory-consistent", "directory-deterministic", "directory-entities-load", "directory-matches-fixture"]),
        "returns a different listing each time": (directory("flaky"), ["directory-deterministic", "directory-matches-fixture"]),
        "returns an empty snapshot when unreachable": (directory("swallows_errors"), ["directory-unreachable-raises"]),
        "returns what it got from a truncated listing": (directory("partial"), ["directory-truncated-raises"]),
    },
    "roles": {
        "load returns the inner object": (roles("unwrapped"), ["roles-load", "roles-malformed", "roles-unknown-key", "roles-write-roundtrip"]),
        "drops unknown keys instead of refusing them": (roles("strips_unknown"), ["roles-unknown-key"]),
        "validates the top level only": (roles("top_level_only"), ["roles-malformed", "roles-unknown-key"]),
        "writes without validating": (roles("no_validation"), ["roles-malformed", "roles-unknown-key"]),
        "load returns what it read at start": (roles("stale"), ["roles-write-roundtrip"]),
        "writes to a draft file the engine does not load": (roles("elsewhere"), ["roles-ceiling-enforced", "roles-write-roundtrip"]),
    },
    "enforcement": {
        "returns the tool's output unmasked": (pep("no_mask"), ["pep-allow-masks", "pep-unmaskable-output"]),
        "runs the tool before asking": (pep("runs_first"), ["pep-approval-id", "pep-budget", "pep-deny-does-not-run", "pep-engine-unreachable", "pep-strict-input", "pep-token-per-call"]),
        "does not check input data strictly": (pep("not_strict"), ["pep-strict-input"]),
        "drops the approval id": (pep("drops_approval"), ["pep-approval-id"]),
        "asks with dry_run": (pep("dry_run"), ["pep-approval-id", "pep-audited", "pep-budget"]),
        "runs the tool when the engine is unreachable": (pep("fail_open"), ["pep-engine-unreachable"]),
        "falls back to the last good token": (pep("caches_token"), ["pep-token-per-call"]),
        "raises on an unknown tool": (pep("unknown_tool_raises"), ["pep-unknown-tool"]),
        "passes plain-text output through": (pep("passes_text"), ["pep-unmaskable-output"]),
    },
    "runtime": {
        "falls back to a service token when there is no task": (runtime("service_account"), ["runtime-no-task", "runtime-spawn-cannot-widen", "runtime-task-token", "runtime-tasks-isolated"]),
        "keeps the token after end_task": (runtime("keeps_token"), ["runtime-task-token"]),
        "keeps the token in a process-wide variable": (runtime("global_token"), ["runtime-tasks-isolated"]),
        "raises on an unregistered tool": (runtime("raises_on_unknown"), ["runtime-unregistered-tool"]),
        "gives the sub-agent the parent's token": (runtime("shares_token"), ["runtime-spawn-cannot-widen", "runtime-spawn-narrows"]),
        "ignores the capability asked for the sub-agent": (runtime("ignores_capability"), ["runtime-spawn-cannot-widen", "runtime-spawn-narrows"]),
        "falls back to the parent's token when the engine refuses": (runtime("falls_back"), ["runtime-spawn-cannot-widen"]),
        "issues a fresh root token for the sub-agent": (runtime("fresh_root"), ["runtime-child-dies-with-parent", "runtime-spawn-cannot-widen", "runtime-spawn-narrows"]),
    },
    "approval": {
        "shows the human the approval id only": (channel("minimal_payload"), ["approval-delivers"]),
        "approves when nobody answers": (channel("auto_approve"), ["approval-own-requests-only", "approval-silence"]),
        "reads any truthy reply as approval": (channel("loose"), ["approval-silence"]),
        "ignores the approve flag": (channel("ignores_flag"), ["approval-reject", "approval-silence"]),
        "returns the same verdict again": (channel("never_drained"), ["approval-names-approver"]),
        "approves as a service account": (channel("service_account"), ["approval-names-approver", "approval-not-laundered", "approval-own-requests-only"]),
        "approves as a fixed person": (channel("fixed_approver"), ["approval-not-laundered"]),
        "applies one approval to every open request": (channel("broadcast"), ["approval-own-requests-only"]),
    },
    "audit": {
        "reports its first record as the head": (sink("head_is_first"), ["audit-head", "audit-replay", "audit-restart", "audit-rewrite"]),
        "refuses records it already holds": (sink("rejects_replay"), ["audit-replay"]),
        "accepts a gap in the sequence": (sink("accepts_gaps"), ["audit-gap"]),
        "does not check hashes": (sink("no_chain_check"), ["audit-chain"]),
        "skips held sequence numbers without comparing": (sink("ignores_rewrite"), ["audit-rewrite"]),
        "keeps its records in memory": (sink("in_memory"), ["audit-restart"]),
    },
    "revocation": {
        "returns events in the order published": (feed("unordered"), ["feed-order"]),
        "ignores the cursor": (feed("ignores_after"), ["feed-order", "feed-reaches-verifier", "feed-restart"]),
        "stores a replayed event twice": (feed("duplicates"), ["feed-order", "feed-replay"]),
        "keeps its events in memory": (feed("in_memory"), ["feed-restart"]),
        "loses who revoked": (feed("drops_by"), ["feed-fidelity"]),
        "carries token revocations only": (feed("tokens_only"), ["feed-fidelity", "feed-order", "feed-reaches-verifier", "feed-replay", "feed-restart"]),
    },
}


class ContractKit(unittest.TestCase):
    def test_reference_implementations_pass_every_check(self):
        for name in INTERFACES:
            results = contract.run(name, FACTORIES[name])
            self.assertTrue(results, name)
            self.assertEqual([f"{r.id}: {r.detail}" for r in results if not r.ok], [], name)
        self.assertEqual(failed("approval", approval_webhook), [])

    def test_each_broken_implementation_is_caught(self):
        for name in INTERFACES:
            for what, (factory, expected) in BROKEN[name].items():
                with self.subTest(interface=name, broken=what):
                    got = failed(name, factory)
                    self.assertTrue(got, f"{name}: an implementation that {what} passed every check")
                    if expected is not None:
                        self.assertEqual(got, expected)

    def test_every_check_is_caught_by_some_broken_implementation(self):
        for name in INTERFACES:
            caught = set()
            for factory, _ in BROKEN[name].values():
                caught.update(failed(name, factory))
            self.assertEqual(sorted(c.id for c in contract.checks_for(name) if c.id not in caught), [], name)

    def test_check_ids_are_unique_and_every_interface_has_checks(self):
        ids = [c.id for c in contract.CHECKS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sorted({c.interface for c in contract.CHECKS}), INTERFACES)
        self.assertEqual(sorted(interfaces.INTERFACES), INTERFACES)
        self.assertEqual(sorted(FACTORIES), INTERFACES)

    def test_reference_classes_satisfy_the_protocols(self):
        with kit.Lab() as lab:
            engine = lab.engine()
            made = {"identity": kit._idp(FACTORIES["identity"])[0], "directory": FACTORIES["directory"](), "roles": FACTORIES["roles"](str(BUNDLE)),
                    "enforcement": AdapterEnforcementPoint(engine), "runtime": SimpleRuntime(engine), "approval": ConsoleApprovalChannel(lambda p: None),
                    "audit": JsonlAuditSink(lab.dir / "a.jsonl"), "revocation": FileRevocationFeed(lab.dir / "f.jsonl")}
            for name, obj in made.items():
                self.assertIsInstance(obj, interfaces.INTERFACES[name], name)
            self.assertIsInstance(WebhookApprovalChannel(lambda body: None), interfaces.ApprovalChannel)
            self.assertNotIsInstance(object(), interfaces.EnforcementPoint)

    def test_a_check_that_crashes_is_a_failure_not_an_exception(self):
        results = contract.run("enforcement", lambda backend, tools: object())
        self.assertTrue(results and all(not r.ok for r in results))
        self.assertIn("AttributeError", results[0].detail)

    def test_unittest_base_class(self):
        good = contract.contract_testcase("audit", FACTORIES["audit"])
        bad = contract.contract_testcase("audit", sink("accepts_gaps"))
        self.assertEqual(sorted(n for n in dir(good) if n.startswith("test_")), sorted("test_" + c.id.replace("-", "_") for c in contract.checks_for("audit")))
        for case, failures in ((good, 0), (bad, 1)):
            result = unittest.TestResult()
            unittest.defaultTestLoader.loadTestsFromTestCase(case).run(result)
            self.assertEqual((result.testsRun, len(result.failures), len(result.errors)), (6, failures, 0))
        with self.assertRaises(ValueError):
            contract.contract_testcase("nope", lambda: None)

    def test_command_line(self):
        run = lambda *args: subprocess.run([sys.executable, "-m", "interfaces.contract", *args], capture_output=True, text=True, cwd=str(ROOT), env=ENV)
        r = run("--reference")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"{len(contract.CHECKS)} checks, 0 failed", r.stdout)
        r = run("--list", "--json")
        listed = json.loads(r.stdout)
        self.assertEqual([c["id"] for c in listed["checks"]], [c.id for c in contract.CHECKS])
        self.assertEqual(sorted(listed["factories"]), INTERFACES)
        r = run("--audit", "interfaces.reference:audit", "--revocation", "interfaces.reference.revocation", "--json")
        self.assertEqual((r.returncode, len(json.loads(r.stdout))), (0, 11))
        r = run("--enforcement", "interfaces.reference:enforcement", "--only", "pep-budget")
        self.assertIn("1 checks, 0 failed", r.stdout)
        broken = Path(tempfile.mkdtemp(prefix="smartdelegate-kit-"))
        self.addCleanup(shutil.rmtree, broken, True)
        (broken / "mypep.py").write_text("from interfaces.contracts import Outcome\n"
                                         "class Open:\n"
                                         "    def __init__(self, backend, tools): self.tools = tools\n"
                                         "    def invoke(self, token, tool, arguments): return Outcome(True, self.tools[tool][1](**arguments))\n", encoding="utf-8")
        r = subprocess.run([sys.executable, "-m", "interfaces.contract", "--enforcement", "mypep:Open"], capture_output=True, text=True, cwd=str(ROOT),
                           env={**ENV, "PYTHONPATH": ENV["PYTHONPATH"] + os.pathsep + str(broken)})
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL pep-deny-does-not-run", r.stdout)
        self.assertIn("FAIL pep-engine-unreachable", r.stdout)
        for args in (["--enforcement"], ["--nope", "x"], ["--enforcement", "no.such.module:x"], ["--enforcement", "interfaces.reference:nope"], []):
            self.assertEqual(run(*args).returncode, 2, args)

    def test_each_contract_page_lists_its_checks(self):
        pages = {"identity": "IdentitySource", "directory": "DirectorySource", "roles": "RoleCatalog", "enforcement": "EnforcementPoint",
                 "runtime": "AgentRuntime", "approval": "ApprovalChannel", "audit": "AuditSink", "revocation": "RevocationFeed"}
        for name, page in pages.items():
            text = (ROOT / "interfaces" / "docs" / f"{page}.md").read_text(encoding="utf-8")
            listed = sorted(set(__import__("re").findall(r"`((?:identity|directory|roles|pep|runtime|approval|audit|feed)-[a-z-]+)`", text)))
            self.assertEqual(listed, sorted(c.id for c in contract.checks_for(name)), page)
            for heading in ("## Contract", "## Fails closed", "## Security notes", "## Other languages", "## Reference implementation", "## Checks"):
                self.assertIn(heading, text, f"{page}: {heading}")


class References(unittest.TestCase):
    """What the reference implementations do beyond the shared checks."""

    def setUp(self):
        self.lab = kit.Lab()
        self.addCleanup(self.lab.close)

    def test_identity_source_configuration_and_presets(self):
        jwks = json.loads((OIDC / "jwks.json").read_text(encoding="utf-8"))
        tokens = json.loads((OIDC / "id_tokens.json").read_text(encoding="utf-8"))
        with self.assertRaises(IdentityError):
            JwksIdentitySource("https://idp.example.test", "smartdelegate-demo", {"keys": []})
        plain = JwksIdentitySource("https://idp.example.test", "smartdelegate-demo", jwks, groups_claim=None)
        self.assertEqual(plain.identify(tokens["bob_both"]), Identity("bob", [], "https://idp.example.test", 4102444800))
        nested = JwksIdentitySource("https://idp.example.test", "smartdelegate-demo", jwks,
                                    rule={"provider": "keycloak", "sources": ["realm_roles"], "map": {"realm_roles:sg-support": "support"}})
        self.assertEqual(nested.identify(tokens["bob_nested"]).groups, ["support"])
        late = JwksIdentitySource("https://idp.example.test", "smartdelegate-demo", jwks, clock=lambda: 4102444801)
        with self.assertRaises(IdentityError) as cm:
            late.identify(tokens["alice"])
        self.assertEqual(cm.exception.code, "id_token_invalid")
        overage = JwksIdentitySource("https://idp.example.test", "smartdelegate-demo", jwks, rule={"provider": "entra"})
        overage.verify = lambda t: {"sub": "u", "exp": 1, "_claim_names": {"groups": "src1"}}
        with self.assertRaises(IdentityError) as cm:
            overage.identify("x")
        self.assertEqual(cm.exception.code, "claims_overage")

    def test_directory_sync_reloads_then_revokes(self):
        bundle = self.lab.bundle_copy()
        engine = self.lab.engine(bundle=bundle)
        tokens = {u: engine.issue_token("support-bot", user=u, role="support-agent", task="t") for u in ("alice", "bob")}
        calls = []
        real = engine.call
        engine.call = lambda op, payload: (calls.append(op), real(op, payload))[1]
        result = sync_directory(FACTORIES["directory"](), bundle / "entities.json", backend=engine, force=True, dry_run=True)
        self.assertEqual((result["written"], calls), (False, []))
        result = sync_directory(FACTORIES["directory"](), bundle / "entities.json", backend=engine, force=True)
        self.assertEqual(result["diff"]["users_removed"], ["erin"])
        self.assertEqual(result["revoked"], ["erin"])
        self.assertEqual(calls, ["reload", "revoke"])
        engine.call = real
        self.assertEqual(engine.call("issue_token", {"user": "frank", "agent": "support-bot", "role": "support-agent", "task": "t"})["user"], "frank")
        # bob stays in support and supervisors: his token lives. Remove him from the directory and sync again.
        snap = FACTORIES["directory"]().snapshot()
        del snap.users["u-bob"], snap.memberships["u-bob"]
        source = type("One", (), {"snapshot": lambda self: snap})()
        self.assertEqual(sync_directory(source, bundle / "entities.json", backend=engine)["revoked"], ["bob"])
        self.assertEqual(engine.inspect_token(tokens["bob"]["token"])["reason"], "token_revoked")
        self.assertTrue(engine.inspect_token(tokens["alice"]["token"])["valid"])
        # the sync was given no attr_map, so the users' attributes are gone: a row filter on the user's region no longer resolves
        d = engine.call("authorize", {"token": tokens["alice"]["token"], "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}})
        self.assertEqual(d["reason"], "obligation_unresolved")
        with self.assertRaises(DirectoryError):
            sync_directory(FACTORIES["directory"]("truncated"), bundle / "entities.json", backend=engine)
        self.assertNotIn("kit-scim-token", json.dumps(result))

    def test_scim_source_needs_its_credential(self):
        source = ScimDirectorySource(fake_scim.BASE, "KIT_UNSET_VARIABLE", transport=fake_scim.transport(), env={})
        with self.assertRaises(DirectoryError) as cm:
            source.snapshot()
        self.assertEqual(cm.exception.code, "no_credential")

    def test_role_catalog_on_an_empty_or_unreadable_bundle(self):
        empty = self.lab.path("empty")
        catalog = FileRoleCatalog(empty)
        self.assertEqual(catalog.load(), {"roles": {}})
        (empty / "roles.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(interfaces.CatalogError):
            catalog.load()
        catalog.write({"roles": {}})
        self.assertEqual(sorted(p.name for p in empty.iterdir()), ["roles.json"])      # no temporary file left behind

    def test_enforcement_point_register_and_bad_arguments(self):
        engine, tools = self.lab.engine(), kit.Tools()
        pep_ = AdapterEnforcementPoint(engine)
        token = kit.role_token(engine)["token"]
        self.assertEqual(pep_.invoke(token, "get_customer", {"customer_id": "c-1"}).refusal.reason, "unknown_tool")
        binding, fn = tools.bound()["get_customer"]
        pep_.register("get_customer", binding, fn)
        self.assertTrue(pep_.invoke(token, "get_customer", {"customer_id": "c-1"}).allowed)
        self.assertEqual(pep_.invoke(token, "get_customer", "c-1").refusal.reason, "invalid_arguments")
        self.assertEqual(pep_.invoke(token, "get_customer", {"customer_id": ["c-1"]}).refusal.rule, "DELEGATE-INVALID-ARGUMENTS")
        self.assertEqual(len(tools.calls), 1)

    def test_runtime_isolates_two_concurrent_tasks(self):
        engine, tools = self.lab.engine(), kit.Tools()
        rt = SimpleRuntime(engine)
        for name, (binding, fn) in tools.bound().items():
            rt.register(name, binding, fn)
        grants = {u: kit.role_token(engine, user=u) for u in ("alice", "bob")}
        seen, barrier = {}, threading.Barrier(2)

        def work(user):
            rt.begin_task(grants[user]["token"])
            barrier.wait(5)
            seen[user] = engine.inspect_token(rt.current_token())["user"]
            rt.end_task()

        threads = [threading.Thread(target=work, args=(u,)) for u in grants]
        [t.start() for t in threads]
        [t.join(10) for t in threads]
        self.assertEqual(seen, {"alice": "alice", "bob": "bob"})
        with self.assertRaises(ValueError):
            rt.begin_task("")

    def test_approval_pump_and_webhook_channel(self):
        engine, request, aid = kit._held(self.lab)
        posted = []
        hook = WebhookApprovalChannel(posted.append)
        delivered: set = set()
        self.assertEqual(pump(engine, hook, delivered)["delivered"], [aid])
        self.assertEqual(posted[0]["type"], "smartdelegate.approval_request")
        self.assertEqual(pump(engine, hook, delivered)["delivered"], [])              # delivered once, not every round
        self.assertFalse(hook.receive({"approval_id": "someone-elses", "approve": True, "by": "bob"}))
        self.assertFalse(hook.receive({"approval_id": aid, "approve": "true", "by": "bob"}))
        self.assertFalse(hook.receive("approve"))
        self.assertTrue(hook.receive({"approval_id": aid, "approve": True, "by": "bob"}))
        self.assertFalse(hook.receive({"approval_id": aid, "approve": True, "by": "bob"}))   # one reply per request
        self.assertEqual(pump(engine, hook, delivered)["approved"], [aid])
        self.assertEqual(engine.call("authorize", request)["effect"], "allow")

        down = WebhookApprovalChannel(lambda body: (_ for _ in ()).throw(OSError("chat is down")))
        engine.call("authorize", request)                                              # held again: the approval was used
        result = pump(engine, down, set())
        self.assertEqual((result["undelivered"], result["approved"]), ([aid], []))
        stray = type("Stray", (), {"deliver": lambda self, r: None, "verdicts": lambda self: [Verdict("not-pending", True, "bob"), "junk"]})()
        self.assertEqual(pump(engine, stray, set())["approved"], [])

    def test_console_channel_prompts(self):
        import builtins
        import io
        from contextlib import redirect_stdout
        answers = iter(["bob", "y", "", "bob", "maybe"])
        real, builtins.input = builtins.input, lambda prompt="": next(answers)
        try:
            ch = ConsoleApprovalChannel()
            with redirect_stdout(io.StringIO()) as out:
                for i in ("a-1", "a-2", "a-3"):
                    ch.deliver(ApprovalRequest(i, "refund-over-100-eur", "alice", "support-bot", "create", "billing.refund/o-9"))
        finally:
            builtins.input = real
        self.assertEqual(ch.verdicts(), [Verdict("a-1", True, "bob")])
        self.assertIn("agent support-bot, acting for alice", out.getvalue())

    def test_shipping_refuses_a_broken_or_shortened_log(self):
        engine, path, records = kit._log(self.lab)
        target = JsonlAuditSink(self.lab.dir / "copy.jsonl")
        self.assertEqual(ship(path, target, batch=2)["shipped"], len(records))
        self.assertEqual(Path(target.path).read_bytes(), path.read_bytes())            # a byte-for-byte copy
        lines = path.read_text(encoding="utf-8").split("\n")
        path.write_text("\n".join(lines[:1] + [lines[1].replace('"alice"', '"mallory"')] + lines[2:]), encoding="utf-8")
        with self.assertRaises(SinkError) as cm:
            ship(path, target)
        self.assertEqual(cm.exception.code, "audit_broken")
        self.assertEqual(ship(self.lab.dir / "no-such-log.jsonl", JsonlAuditSink(self.lab.dir / "other.jsonl")), {"shipped": 0, "head": None})

    def test_revocations_from_audit_and_a_feed_that_cannot_be_read(self):
        engine = self.lab.engine()
        grant = kit.role_token(engine)
        engine.revoke(grant["token_id"])
        engine.revoke_user("bob", by="hr")
        path = self.lab.dir / "state" / "audit.jsonl"
        events = revocations_from_audit(path)
        self.assertEqual([(e.kind, e.subject, e.by) for e in events], [("token", grant["token_id"], None), ("user", "bob", "hr")])
        self.assertEqual(revocations_from_audit(path, after=events[0].seq), events[1:])
        feed_ = FileRevocationFeed(self.lab.dir / "feed.jsonl")
        feed_.publish(events)
        Path(feed_.path).write_text("{broken\n", encoding="utf-8")
        with self.assertRaises(FeedError):          # not an empty list: "nothing was revoked" would be a lie
            feed_.poll()
        with self.assertRaises(FeedError):
            apply_revocations(engine, [Revocation(1, "group", "x", 0)])
        closed = Engine({"bundle_dir": str(BUNDLE)})
        closed.call = lambda op, payload: {"ok": False, "error": {"code": "state_io"}}
        with self.assertRaises(FeedError) as cm:
            apply_revocations(closed, events)
        self.assertIn(f"event {events[0].seq} was not applied", cm.exception.message)


if __name__ == "__main__":
    unittest.main()
