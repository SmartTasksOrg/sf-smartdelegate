"""The agent-facing surface: skills/, agents/ (with their bundle fragment),
AGENTS.md, llms.txt, the operations tools of the MCP server, and the two
guides docs/INTEGRATE.md and docs/FRAMEWORK.md with spec/iaiso-map.json.

    cd tests && python3 -m unittest test_agent_surface -v

What is proved with engine calls: the role the operator agent runs under can
read the monitoring tools and cannot approve, revoke users, issue tokens for
others or change policy; the same through a governed MCP server.

Standard library only. The Rust port is optional: the one test that needs
its binary is skipped with the reason when it is not built.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import BUNDLE, CLI, ENV, PY, ROOT

sys.path[:0] = [str(ROOT / "skills"), str(ROOT)]

import validate as skill_validator  # noqa: E402
from sf_smartdelegate import Engine, core  # noqa: E402
from sf_smartdelegate.bundle import Bundle  # noqa: E402
from sf_smartdelegate.errors import rule_id  # noqa: E402

SKILLS = ROOT / "skills"
AGENTS = ROOT / "agents"
FRAGMENT = AGENTS / "bundle-example"
SERVER = ROOT / "integrations" / "mcp" / "server.py"
RUST = ROOT / "ports" / "rust" / "target" / "release" / "smartdelegate"
ENV2 = {**ENV, "PYTHONPATH": os.pathsep.join([str(PY), str(ROOT), os.environ.get("PYTHONPATH", "")])}
EXPECTED_SKILLS = ["smartdelegate-delegate", "smartdelegate-enforce", "smartdelegate-explain", "smartdelegate-integrate",
                   "smartdelegate-monitor", "smartdelegate-offboard", "smartdelegate-policy"]
STATUSES = ("implemented in this repo", "interface exists", "proposed, not built")
MONITORING = ["status", "audit_tail", "audit_verify", "pending_approvals", "anomalies"]
QUESTIONS = ["whoami", "roles", "check", "explain", "narrow"]


def run(*argv, stdin=None, cwd=ROOT):
    return subprocess.run([str(a) for a in argv], capture_output=True, text=True, input=stdin, cwd=str(cwd), env=ENV2, timeout=120)


def merged_bundle(target: Path) -> Path:
    """The conformance bundle with the agents' fragment merged in."""
    shutil.copytree(BUNDLE, target)
    r = run(sys.executable, FRAGMENT / "merge.py", "--into", target)
    assert r.returncode == 0, r.stderr
    return target


# ---- skills --------------------------------------------------------------------

class Skills(unittest.TestCase):
    def test_the_skills_are_valid_and_their_commands_exist(self):
        commands, options = skill_validator.cli_surface()
        self.assertIn(("token", "issue"), commands)
        self.assertIn(("bridge", "sync-scim"), commands)
        self.assertIn("--role", options)
        found = sorted(p.name for p in SKILLS.iterdir() if p.is_dir() and not p.name.startswith((".", "_")))
        self.assertEqual(found, EXPECTED_SKILLS)
        for name in found:
            self.assertEqual(skill_validator.validate(SKILLS / name, commands, options, run=True), [], name)

    def test_validator_command_line(self):
        r = run(sys.executable, SKILLS / "validate.py", "--run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"{len(EXPECTED_SKILLS)} skills, 0 problems", r.stdout)
        self.assertEqual(run(sys.executable, SKILLS / "validate.py", "--nope").returncode, 1)

    def test_validator_catches_a_bad_skill(self):
        commands, options = skill_validator.cli_surface()
        tmp = Path(tempfile.mkdtemp(prefix="smartdelegate-skill-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        good = "---\nname: {name}\ndescription: Use when testing the validator, with enough text to pass the length rule.\n---\n" \
               "# T\n\n## Never without a human\n\n- x\n\n## Commands\n\n```bash\n{command}\n```\n"

        def problems(name, text, folder=None):
            d = tmp / (folder or name)
            d.mkdir(exist_ok=True)
            (d / "SKILL.md").write_text(text, encoding="utf-8")
            return " | ".join(skill_validator.validate(d, commands, options))

        self.assertEqual(problems("ok-skill", good.format(name="ok-skill", command="smartdelegate token issue --user alice --agent a --role r --raw")), "")
        self.assertEqual(problems("ok-two", good.format(name="ok-two", command="smartdelegate audit tail -n 5 | python3 skills/validate.py")), "")
        self.assertIn("not the folder name", problems("a-skill", good.format(name="other", command="smartdelegate info")))
        self.assertIn("lower-case", problems("Bad_Name", good.format(name="Bad_Name", command="smartdelegate info")))
        self.assertIn("not a command", problems("b-skill", good.format(name="b-skill", command="smartdelegate token mint --user alice")))
        self.assertIn("not a command", problems("b2-skill", good.format(name="b2-skill", command="smartdelegate grant-all")))
        self.assertIn("option --superuser", problems("c-skill", good.format(name="c-skill", command="smartdelegate token issue --superuser")))
        self.assertIn("network", problems("d-skill", good.format(name="d-skill", command="curl -s http://127.0.0.1:8181/healthz")))
        self.assertIn("URL", problems("e-skill", good.format(name="e-skill", command="smartdelegate info") + "\nSee https://example.com/x\n"))
        self.assertIn("does not exist", problems("f-skill", good.format(name="f-skill", command="python3 skills/no-such/script.py")))
        self.assertIn("not an entry point", problems("g-skill", good.format(name="g-skill", command="python3 -m http.server")))
        self.assertIn("Never without a human", problems("h-skill", good.format(name="h-skill", command="smartdelegate info").replace("## Never without a human", "## Notes")))
        self.assertIn("no front matter", problems("i-skill", "# no front matter\n"))
        self.assertIn("exactly", problems("j-skill", good.format(name="j-skill", command="smartdelegate info").replace("---\n# T", "license: x\n---\n# T")))
        self.assertIn("Use when", problems("k-skill", good.format(name="k-skill", command="smartdelegate info").replace("Use when", "For")))
        self.assertIn("characters", problems("l-skill", "---\nname: l-skill\ndescription: Use when x.\n---\n## Never without a human\n## Commands\n"))
        self.assertIn("not a command", problems("m-skill", good.format(name="m-skill", command="smartdelegate info") + "\nRun `smartdelegate inline-nonsense` now.\n"))

    def test_every_skill_says_what_needs_a_human(self):
        words = {"smartdelegate-delegate": ["issue a root token", "--groups", "wider"], "smartdelegate-enforce": ["approve", "budget"],
                 "smartdelegate-explain": ["issue, widen, approve, revoke"], "smartdelegate-policy": ["unsigned", "widen", "signing key", "by hand"],
                 "smartdelegate-monitor": ["revoke", "approve", "reload", "change policy"], "smartdelegate-offboard": ["human confirming", "exact user id"],
                 "smartdelegate-integrate": ["admin key", "enforced"]}
        for name, needles in words.items():
            text = (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")
            section = text.split("## Never without a human", 1)[1].split("\n## ", 1)[0]
            for needle in needles:
                self.assertIn(needle, section, f"{name}: the 'never' section does not mention {needle!r}")

    def test_rule_table_covers_every_reason_of_the_specification(self):
        sys.path.insert(0, str(SKILLS / "smartdelegate-explain" / "scripts"))
        import rules
        scope = (ROOT / "docs" / "SCOPE.md").read_text(encoding="utf-8")
        reasons = re.findall(r"`([a-z_]+)`", scope.split("machine-readable `reason`:", 1)[1].split("`rule` is the reason", 1)[0])
        self.assertIn("approval_required", reasons)
        api = (ROOT / "spec" / "API.md").read_text(encoding="utf-8")
        errors = [c for line in re.findall(r"Errors: ([^\n]+(?:\n`[^\n]+)?)", api) for c in re.findall(r"`([a-z_]+)`", line)]
        self.assertIn("role_not_held", errors)
        self.assertIn("self_approval", errors)
        missing = sorted({rule_id(c) for c in reasons + errors + ["policy_permit", "shadow_allow"]} - set(rules.RULES))
        self.assertEqual(missing, [])
        for rule, (what, who) in rules.RULES.items():
            self.assertRegex(rule, r"^DELEGATE-[A-Z]+(-[A-Z]+)*$")
            self.assertTrue(what and who, rule)

    def test_helper_scripts_on_a_real_audit_log(self):
        state = tempfile.mkdtemp(prefix="smartdelegate-skills-")
        self.addCleanup(shutil.rmtree, state, True)
        cfg = ["--bundle", BUNDLE, "--state", os.path.join(state, "s")]
        cli = lambda *a: run(*CLI, *a, *cfg)
        token = cli("token", "issue", "--user", "alice", "--agent", "support-bot", "--role", "support-agent", "--task", "ticket-7", "--raw").stdout.strip()
        bob = cli("token", "issue", "--user", "bob", "--agent", "support-bot", "--role", "support-agent", "--task", "ticket-8", "--raw").stdout.strip()
        for i in range(5):
            self.assertEqual(cli("authorize", "--token", token, "--action", "read", "--resource", f"hr.salary/e-{i}").returncode, 2)
        denied = json.loads(cli("authorize", "--token", token, "--action", "read", "--resource", "hr.salary/e-9").stdout)
        tail = cli("audit", "tail", "-n", "100").stdout

        live = lambda user: run(sys.executable, SKILLS / "smartdelegate-offboard" / "scripts" / "live_tokens.py", "--user", user, stdin=tail)
        r = live("alice")
        self.assertEqual((r.returncode, len(json.loads(r.stdout)["live_tokens"])), (3, 1))

        r = run(sys.executable, SKILLS / "smartdelegate-monitor" / "scripts" / "audit_summary.py", "--json", stdin=tail)
        summary = json.loads(r.stdout)
        self.assertEqual(r.returncode, 3)
        self.assertEqual(summary["by_rule"], {"DELEGATE-CAPABILITY-RESOURCE": 6})
        self.assertEqual([(f["code"], f["subject"], f["count"]) for f in summary["findings"]], [("capability_probing", "support-bot", 6)])
        text = run(sys.executable, SKILLS / "smartdelegate-monitor" / "scripts" / "audit_summary.py", stdin=tail).stdout
        self.assertIn("FINDING code=capability_probing", text)
        self.assertEqual(run(sys.executable, SKILLS / "smartdelegate-monitor" / "scripts" / "audit_summary.py", stdin="").returncode, 0)

        r = run(sys.executable, SKILLS / "smartdelegate-explain" / "scripts" / "rules.py", "--decision", denied["decision_id"], stdin=tail)
        self.assertEqual(r.returncode, 0, r.stderr)
        for part in ("user alice via support-bot", "read hr.salary/e-9", "DELEGATE-CAPABILITY-RESOURCE", "who can change it"):
            self.assertIn(part, r.stdout)
        self.assertEqual(run(sys.executable, SKILLS / "smartdelegate-explain" / "scripts" / "rules.py", "--decision", "d-nope", stdin=tail).returncode, 1)
        self.assertEqual(run(sys.executable, SKILLS / "smartdelegate-explain" / "scripts" / "rules.py", "DELEGATE-NOPE").returncode, 1)
        self.assertIn("DELEGATE-WIDENING", run(sys.executable, SKILLS / "smartdelegate-explain" / "scripts" / "rules.py", "--all").stdout)

        # the offboarding skill's steps 4 and 5: revoke with attribution, then verify
        r = cli("call", "revoke", "--input", '{"user": "alice", "by": "jane.doe"}')
        self.assertEqual(json.loads(r.stdout)["revoked_user"], "alice")
        tail = cli("audit", "tail", "-n", "100").stdout
        r = live("alice")
        out = json.loads(r.stdout)
        self.assertEqual((r.returncode, out["live_tokens"], out["user_revoked_records"]), (0, [], 1))
        self.assertEqual(live("bob").returncode, 3)                    # nobody revoked bob
        self.assertEqual(json.loads(cli("token", "inspect", "--token", token).stdout)["reason"], "token_revoked")
        self.assertTrue(json.loads(cli("token", "inspect", "--token", bob).stdout)["valid"])
        self.assertEqual(json.loads(tail.strip().split("\n")[-1])["by"], "jane.doe")
        self.assertEqual(run(sys.executable, SKILLS / "smartdelegate-offboard" / "scripts" / "live_tokens.py").returncode, 2)

    def test_the_enforce_example_runs(self):
        r = run(sys.executable, SKILLS / "smartdelegate-enforce" / "scripts" / "wrap_tool.py")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["read"], {"id": "c-1", "name": "Ada Lovelace", "email": "ada@example.com", "region": "EU"})
        self.assertEqual((out["update_with_ssn"]["rule"], out["refund_60"], out["refund_60_again"]["rule"]),
                         ("DELEGATE-FIELD-DENIED", {"order_id": "o-1"}, "DELEGATE-BUDGET-EXCEEDED"))
        self.assertIn("A human can approve it with id", out["refund_150"]["text_for_the_model"])


# ---- agents and their bundle fragment --------------------------------------------

def agent_file(name: str) -> tuple:
    fields, body = skill_validator.front_matter((AGENTS / f"{name}.md").read_text(encoding="utf-8"))
    return fields, body, json.loads(re.search(r"```json\n(.*?)```", body, re.S).group(1))


class AgentDefinitions(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="smartdelegate-agents-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def engine(self, bundle, name="state") -> Engine:
        e = Engine({"bundle_dir": str(bundle), "state_dir": str(self.tmp / name), "require_role": True})
        self.addCleanup(e.close)
        return e

    def test_each_agent_states_the_role_and_ceiling_the_bundle_gives_it(self):
        roles = json.loads((FRAGMENT / "roles.json").read_text(encoding="utf-8"))["roles"]
        for name, role in (("smartdelegate-operator", "sd-operator"), ("smartdelegate-integrator", "sd-integrator")):
            fields, body, stated = agent_file(name)
            self.assertEqual(sorted(fields), ["description", "name", "tools"])
            self.assertEqual(fields["name"], name)
            self.assertGreaterEqual(len(fields["description"]), 80)
            self.assertEqual((stated["agent"], stated["role"]), (name, role))
            self.assertEqual(stated["ceiling"], roles[role]["cap"])
            self.assertEqual((stated["max_ttl"], [stated["task"]], [stated["agent"]]), (roles[role]["max_ttl"], roles[role]["tasks"], roles[role]["agents"]))
            for heading in ("## The delegation this agent runs under", "## What you do", "## What you never do"):
                self.assertIn(heading, body, name)
            tools = [t.strip() for t in fields["tools"].split(",")]
            self.assertFalse([t for t in tools if t.rsplit("__", 1)[-1] in ("delegate", "approve", "revoke_user", "reload")], name)
            # every monitoring tool the agent lists is one its role's ceiling covers
            listed = {t.rsplit("__", 1)[-1] for t in tools if t.startswith("mcp__smartdelegate__")} - set(QUESTIONS)
            self.assertEqual(listed, {r.split("/", 1)[1] for r in roles[role]["cap"]["resources"]}, name)
        operator = (AGENTS / "smartdelegate-operator.md").read_text(encoding="utf-8")
        self.assertNotIn("Edit", agent_file("smartdelegate-operator")[0]["tools"])
        for word in ("Escalate immediately", "Preparing a privileged action", "Report format"):
            self.assertIn(word, operator)

    def test_fragment_loads_alone_and_its_policy_tests_pass(self):
        b = Bundle(FRAGMENT)
        self.assertEqual(sorted(b.roles), ["sd-integrator", "sd-operator"])
        self.assertEqual(sorted(b.catalog), ["smartdelegate.ops"])
        self.assertFalse((FRAGMENT / "bundle.sig.json").exists())
        r = run(*CLI, "policy", "test", "--bundle", FRAGMENT)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("4 tests, 0 failed", r.stdout)
        for rdef in json.loads((FRAGMENT / "roles.json").read_text(encoding="utf-8"))["roles"].values():
            self.assertTrue(rdef["max_ttl"] and rdef["tasks"] and rdef["agents"])
            self.assertEqual(rdef["cap"]["actions"], ["read"])
            self.assertFalse([r for r in rdef["cap"]["resources"] if r.endswith("*")])

    def test_operator_role_reads_and_cannot_approve_revoke_issue_or_change_policy(self):
        engine = self.engine(merged_bundle(self.tmp / "bundle"))
        ask = lambda token, action, tool: engine.call("authorize", {"token": token, "action": action, "resource": {"path": "smartdelegate.ops", "id": tool}})
        issue = lambda **kw: engine.call("issue_token", {"user": "olivia", "agent": "smartdelegate-operator", "role": "sd-operator", "task": "ops-daily", **kw})

        grant = issue()
        self.assertTrue(grant["ok"], grant)
        self.assertEqual((grant["role"], grant["expires_in"], grant["cap"]["actions"]), ("sd-operator", 900, ["read"]))
        token = grant["token"]

        # can: read every monitoring tool; each call is a decision in the audit log, attributed
        for tool in MONITORING:
            d = ask(token, "read", tool)
            self.assertEqual((d["effect"], d["policies"]), ("allow", ["ops-operator-reads-monitoring"]), tool)
        last = engine.call("audit_tail", {"n": 1})["records"][0]
        self.assertEqual((last["user"], last["chain"], last["role"], last["resource"]), ("olivia", ["smartdelegate-operator"], "sd-operator", "smartdelegate.ops/anomalies"))

        # cannot: any privileged tool, by action or by resource
        for tool in ("approve", "revoke_user", "reload", "delegate"):
            self.assertEqual(ask(token, "operate", tool)["reason"], "capability_action", tool)
            self.assertEqual(ask(token, "read", tool)["reason"], "capability_resource", tool)

        # cannot: get more out of the role. The ceiling refuses it at issuance ...
        for cap in ({"actions": ["read", "operate"], "resources": ["smartdelegate.ops/status"]},
                    {"actions": ["read"], "resources": ["smartdelegate.ops/*"]},
                    {"actions": ["read"], "resources": ["smartdelegate.ops/status", "smartdelegate.ops/revoke_user"]},
                    {"actions": ["read"], "resources": ["crm.customer/*"]}):
            self.assertEqual(issue(cap=cap)["error"]["code"], "role_exceeded", cap)
        # ... and if a ceiling were ever widened by mistake, policy still forbids these roles to operate
        wide = Engine({"bundle_dir": str(self.tmp / "bundle"), "trust_caller_chain": True, "audit": False})
        self.addCleanup(wide.close)
        d = wide.call("authorize", {"chain": {"user": "olivia", "agents": ["smartdelegate-operator"], "role": "sd-operator"}, "action": "operate",
                                    "resource": {"path": "smartdelegate.ops", "id": "revoke_user"}})
        self.assertEqual((d["reason"], d["policies"]), ("policy_forbid", ["ops-agent-roles-never-operate"]))

        # cannot: issue tokens for others. The role is lent only by its holders, to this agent, for an ops task
        self.assertEqual(issue(user="alice")["error"]["code"], "role_not_held")
        self.assertEqual(issue(user="ian")["error"]["code"], "role_not_held")
        self.assertEqual(issue(agent="support-bot")["error"]["code"], "role_exceeded")
        self.assertEqual(issue(task="ticket-7")["error"]["code"], "role_exceeded")
        self.assertEqual(issue(ttl=7200)["expires_in"], 900)
        # ... and the operator's token cannot be handed on, to anyone, nor turned into another role
        for actor in ("summarizer", "support-bot", "smartdelegate-integrator", "smartdelegate-operator"):
            self.assertEqual(engine.call("exchange_token", {"subject_token": token, "actor": actor})["error"]["code"], "delegation_denied", actor)
        self.assertEqual(engine.call("exchange_token", {"subject_token": token, "actor": "summarizer", "role": "support-agent"})["error"]["code"], "widening")
        # ... and it reaches no business data
        self.assertEqual(engine.call("authorize", {"token": token, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}})["reason"], "capability_resource")

        # cannot: approve. A request is held (by an engine on the same bundle and state that still issues bare
        # capabilities); the operator's human is not someone policy lets approve
        other = Engine({"bundle_dir": str(self.tmp / "bundle"), "state_dir": str(self.tmp / "state")})
        self.addCleanup(other.close)
        t = other.issue_token("support-bot", {"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 20000}}, user="alice")
        held = other.call("authorize", {"token": t["token"], "action": "create", "resource": {"path": "billing.refund", "id": "o-1"},
                                        "context": {"spend": {"currency": "EUR", "amount": 15000}}})
        self.assertEqual(held["reason"], "approval_required", held)
        aid = held["approval"]["id"]
        for by in ("olivia", "ian"):
            self.assertEqual(engine.call("approve", {"approval_id": aid, "by": by})["error"]["code"], "approval_denied", by)
        self.assertIn(aid, engine.call("approvals", {})["pending"])
        self.assertTrue(engine.call("approve", {"approval_id": aid, "by": "bob"})["ok"])    # a supervisor can

    def test_integrator_role_reads_status_only(self):
        engine = self.engine(merged_bundle(self.tmp / "bundle"))
        grant = engine.call("issue_token", {"user": "ian", "agent": "smartdelegate-integrator", "role": "sd-integrator", "task": "integrate-crm"})
        self.assertTrue(grant["ok"], grant)
        ask = lambda action, tool: engine.call("authorize", {"token": grant["token"], "action": action, "resource": {"path": "smartdelegate.ops", "id": tool}})
        self.assertEqual(ask("read", "status")["effect"], "allow")
        for tool in MONITORING[1:] + ["approve", "revoke_user", "reload", "delegate"]:
            self.assertEqual(ask("read", tool)["reason"], "capability_resource", tool)
            self.assertEqual(ask("operate", tool)["reason"], "capability_action", tool)
        self.assertEqual(engine.call("issue_token", {"user": "olivia", "agent": "smartdelegate-integrator", "role": "sd-integrator", "task": "integrate-x"})["error"]["code"],
                         "role_not_held")

    def test_merge_adds_and_never_overwrites(self):
        target = merged_bundle(self.tmp / "bundle")
        b = Bundle(target)
        self.assertEqual(sorted(b.roles), ["auditor", "break-glass", "sd-integrator", "sd-operator", "supervisor", "support-agent"])
        self.assertEqual(len(b.policies), 26)
        self.assertEqual(run(*CLI, "policy", "test", "--bundle", target).returncode, 0)
        before = {p.name: p.read_bytes() for p in target.iterdir() if p.is_file()}
        r = run(sys.executable, FRAGMENT / "merge.py", "--into", target)            # a second merge collides with the first
        self.assertEqual(r.returncode, 1)
        self.assertIn("nothing was written", r.stderr)
        self.assertEqual({p.name: p.read_bytes() for p in target.iterdir() if p.is_file()}, before)

        clash = self.tmp / "clash"
        shutil.copytree(BUNDLE, clash)
        roles = json.loads((clash / "roles.json").read_text(encoding="utf-8"))
        roles["roles"]["sd-operator"] = dict(roles["roles"]["auditor"])              # the adopter already has a role of that name
        (clash / "roles.json").write_text(json.dumps(roles), encoding="utf-8")
        r = run(sys.executable, FRAGMENT / "merge.py", "--into", clash)
        self.assertEqual(r.returncode, 1)
        self.assertIn("nothing is overwritten", r.stderr)
        self.assertFalse((clash / "policies" / "ops.cedar").exists())
        dry = self.tmp / "dry"
        shutil.copytree(BUNDLE, dry)
        r = run(sys.executable, FRAGMENT / "merge.py", "--into", dry, "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((dry / "policies" / "ops.cedar").exists())
        self.assertEqual(run(sys.executable, FRAGMENT / "merge.py").returncode, 1)
        self.assertEqual(run(sys.executable, FRAGMENT / "merge.py", "--into", self.tmp / "no-such-bundle").returncode, 1)

    @unittest.skipUnless(RUST.exists(), "the Rust port is not built (ports/rust/target/release/smartdelegate): it is the only compiler of .cedar files")
    def test_compiled_policies_are_what_the_rust_port_produces(self):
        for name, source in (("fragment", FRAGMENT), ("merged", merged_bundle(self.tmp / "bundle"))):
            copy = self.tmp / f"compile-{name}"
            shutil.copytree(source, copy)
            committed = json.loads((copy / "policies.json").read_text(encoding="utf-8"))
            r = run(RUST, "bundle", "compile", "--bundle", copy)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads((copy / "policies.json").read_text(encoding="utf-8")), committed, name)


# ---- the MCP server's operations tools ------------------------------------------

class Session:
    def __init__(self, bundle, state, *flags, env=None):
        self.proc = subprocess.Popen([sys.executable, str(SERVER), "--bundle", str(bundle), "--state", str(state), *flags], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1, env={**ENV, **(env or {})})
        self.n = 0

    def request(self, method, params=None):
        self.n += 1
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, **({"params": params} if params is not None else {})}) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise AssertionError("the MCP server exited: " + self.proc.stderr.read())
        return json.loads(line)

    def names(self):
        return [t["name"] for t in self.request("tools/list")["result"]["tools"]]

    def tool(self, name, **arguments):
        """-> (isError, structured result)"""
        reply = self.request("tools/call", {"name": name, "arguments": arguments})
        if "error" in reply:
            return "protocol", reply["error"]
        return reply["result"]["isError"], reply["result"]["structuredContent"]

    def code(self, name, **arguments):
        is_error, out = self.tool(name, **arguments)
        return out["error"]["code"] if is_error is True else (out["code"] if is_error == "protocol" else None)

    def close(self):
        self.proc.stdin.close()
        code = self.proc.wait(timeout=20)
        err = self.proc.stderr.read()
        self.proc.stdout.close()
        self.proc.stderr.close()
        return code, err


class McpOperations(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="smartdelegate-mcp-ops-"))
        self.state = self.tmp / "state"
        self.sessions = []
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def tearDown(self):
        for s in self.sessions:
            if s.proc.poll() is None:
                s.proc.kill()
                s.proc.wait()
                for f in (s.proc.stdin, s.proc.stdout, s.proc.stderr):
                    f.close()

    def session(self, *flags, bundle=BUNDLE, env=None) -> Session:
        s = Session(bundle, self.state, *flags, env=env)
        self.sessions.append(s)
        return s

    def engine(self, bundle=BUNDLE) -> Engine:
        e = Engine({"bundle_dir": str(bundle), "state_dir": str(self.state)})
        self.addCleanup(e.close)
        return e

    def test_which_tools_are_listed_under_which_flags(self):
        cases = {(): QUESTIONS, ("--ops",): QUESTIONS + MONITORING, ("--admin",): QUESTIONS + ["delegate"],
                 ("--ops", "--admin"): QUESTIONS + MONITORING + ["delegate"],
                 ("--admin", "--allow-tools", "revoke_user"): QUESTIONS + ["revoke_user"],
                 ("--admin", "--allow-tools", "delegate,approve,revoke_user,reload"): QUESTIONS + ["approve", "revoke_user", "reload", "delegate"],
                 ("--ops", "--govern"): QUESTIONS + MONITORING}
        for flags, expected in cases.items():
            s = self.session(*flags)
            self.assertEqual(s.names(), expected, flags)
            for t in s.request("tools/list")["result"]["tools"]:
                self.assertTrue(t["description"] and t["inputSchema"]["type"] == "object" and t["inputSchema"]["additionalProperties"] is False)
            s.close()
        for flags, message in ((("--allow-tools", "revoke_user"), "--allow-tools needs --admin"), (("--admin", "--allow-tools", "drop_tables"), "not a privileged tool"),
                               (("--ops", "--bogus", "x"), "unknown option")):
            r = subprocess.run([sys.executable, str(SERVER), "--bundle", str(BUNDLE), *flags], capture_output=True, text=True, env=ENV, stdin=subprocess.DEVNULL)
            self.assertEqual(r.returncode, 1, flags)
            self.assertIn(message, r.stderr)
        self.assertIn("--allow-tools", subprocess.run([sys.executable, str(SERVER), "--help"], capture_output=True, text=True, env=ENV).stdout)

    def test_monitoring_and_privileged_tools_are_off_by_default(self):
        s = self.session()
        for tool in MONITORING:
            self.assertEqual(s.code(tool), "ops_required", tool)
        for tool, args in (("approve", {"approval_id": "x", "by": "bob"}), ("revoke_user", {"user": "alice", "by": "x"}), ("reload", {"by": "x"})):
            self.assertEqual(s.code(tool, **args), "admin_required", tool)
        a = self.session("--ops", "--admin")                        # --admin alone still means: delegate only
        for tool, args in (("approve", {"approval_id": "x", "by": "bob"}), ("revoke_user", {"user": "alice", "by": "x"}), ("reload", {"by": "x"})):
            is_error, out = a.tool(tool, **args)
            self.assertEqual((is_error, out["error"]["code"], out["error"]["rule"]), (True, "tool_not_allowed", "DELEGATE-TOOL-NOT-ALLOWED"), tool)
        one = self.session("--admin", "--allow-tools", "revoke_user")
        self.assertEqual(one.code("delegate", user="alice", agent="support-bot", role="support-agent", task="t"), "tool_not_allowed")
        for s_ in (s, a, one):
            s_.close()
        with self.engine() as e:
            self.assertEqual(e.call("audit_verify", {})["records"], 0)          # nothing happened

    def test_status_audit_and_pending_approvals(self):
        e = self.engine()
        alice = e.issue_token("support-bot", user="alice", role="support-agent", task="ticket-7")
        wide = e.issue_token("support-bot", {"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 20000}}, user="alice")
        e.authorize(alice["token"], "read", "crm.customer", "c-1")
        denied = e.authorize(alice["token"], "read", "hr.salary", "e-1")
        held = e.authorize(wide["token"], "create", "billing.refund", "o-9", context={"spend": {"currency": "EUR", "amount": 15000}})
        s = self.session("--ops")

        _, st = s.tool("status")
        self.assertEqual((st["version"], st["mode"], st["policy_version"]), (e.info()["version"], "enforce", e.info()["policy_version"]))
        self.assertEqual(st["roles"], ["auditor", "break-glass", "supervisor", "support-agent"])
        self.assertEqual(st["counts"], {"policies": 21, "resources": 3, "roles": 4, "audit_records": 5, "pending_approvals": 1, "granted_approvals": 0})
        self.assertEqual((st["audit"]["chain"], st["audit"]["head"]), ("verifies", e.call("audit_verify", {})["head"]))
        self.assertIsNone(st["directory_sync"])
        self.assertEqual(st["server"], {"ops": True, "admin": False, "privileged_tools": [], "govern": False})
        self.assertTrue(any("not signature-checked" in w for w in st["warnings"]))
        self.assertTrue(any("require_role is off" in w for w in st["warnings"]))
        self.assertNotIn("public_key", st)

        _, v = s.tool("audit_verify")
        self.assertEqual((v["records"], v["head"]), (5, st["audit"]["head"]))

        _, tail = s.tool("audit_tail")
        self.assertEqual([r["event"] for r in tail["records"]], ["token_issued", "token_issued", "decision", "decision", "decision"])
        self.assertEqual([r.get("rule") for r in tail["records"]][2:], ["DELEGATE-POLICY-PERMIT", "DELEGATE-CAPABILITY-RESOURCE", "DELEGATE-APPROVAL-REQUIRED"])
        self.assertEqual(len(s.tool("audit_tail", n=2)[1]["records"]), 2)
        self.assertEqual([r["decision_id"] for r in s.tool("audit_tail", n=50, rule="DELEGATE-CAPABILITY-RESOURCE")[1]["records"]], [denied["decision_id"]])
        self.assertEqual(len(s.tool("audit_tail", n=50, decision_id=denied["decision_id"])[1]["records"]), 1)
        self.assertEqual(len(s.tool("audit_tail", n=50, event="token_issued", user="alice")[1]["records"]), 2)
        self.assertEqual(s.tool("audit_tail", n=50, user="mallory")[1]["records"], [])
        text = json.dumps(tail)
        self.assertNotIn(alice["token"], text)
        for bad in ({"n": 0}, {"n": "5"}, {"n": True}, {"since": 3}):
            self.assertEqual(s.code("audit_tail", **bad), -32602, bad)

        _, p = s.tool("pending_approvals")
        self.assertEqual((len(p["pending"]), p["granted"]), (1, 0))
        self.assertEqual({k: p["pending"][0][k] for k in ("id", "label", "user", "agent", "action", "resource")},
                         {"id": held["approval"]["id"], "label": "refund-over-100-eur", "user": "alice", "agent": "support-bot", "action": "create",
                          "resource": "billing.refund/o-9"})
        self.assertGreaterEqual(p["pending"][0]["age_seconds"], 0)
        s.close()
        self.assertEqual(e.call("audit_verify", {})["records"], 5)            # the monitoring tools wrote nothing

    def test_status_warns_about_a_stale_sync_shadow_mode_and_a_broken_chain(self):
        bundle = self.tmp / "bundle"
        shutil.copytree(BUNDLE, bundle)
        (bundle / "entities.sync.json").write_text(json.dumps({"source": "scim:test", "synced_at": "2020-01-01T00:00:00Z"}), encoding="utf-8")
        e = self.engine(bundle)
        t = e.issue_token("support-bot", user="alice", role="support-agent", task="t")
        e.authorize(t["token"], "read", "hr.salary", "e-1")
        s = self.session("--ops", "--shadow", bundle=bundle)
        _, st = s.tool("status")
        self.assertEqual((st["mode"], st["directory_sync"]["source"]), ("shadow", "scim:test"))
        self.assertGreater(st["directory_sync"]["age_seconds"], 86400 * 365)
        self.assertTrue(any("shadow mode" in w for w in st["warnings"]))
        log = self.state / "audit.jsonl"
        log.write_text(log.read_text(encoding="utf-8").replace('"alice"', '"mallory"', 1), encoding="utf-8")
        _, st = s.tool("status")
        self.assertEqual(st["audit"]["chain"], "broken")
        self.assertTrue(any("does not verify" in w for w in st["warnings"]))
        is_error, out = s.tool("audit_verify")
        self.assertEqual((is_error, out["error"]["code"]), (True, "audit_broken"))
        self.assertEqual([f["code"] for f in s.tool("anomalies")[1]["findings"] if f["severity"] == "critical"], ["audit_chain_broken"])

    def test_anomalies(self):
        e = self.engine()
        alice = e.issue_token("support-bot", user="alice", role="support-agent", task="ticket-7")
        bob = e.issue_token("support-bot", user="bob", role="support-agent", task="ticket-8")
        carol = e.issue_token("support-bot", {"actions": ["read"], "resources": ["hr.salary/*"]}, user="carol")
        wide = e.issue_token("support-bot", {"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 20000}}, user="alice")
        for i in range(5):
            e.authorize(alice["token"], "read", "hr.salary", f"e-{i}")                         # 5 x capability_resource by support-bot
        e.authorize(alice["token"], "create", "billing.refund", "o-1", context={"spend": {"currency": "EUR", "amount": 9000}})
        for i in range(3):
            e.authorize(alice["token"], "create", "billing.refund", f"o-{i + 2}", context={"spend": {"currency": "EUR", "amount": 9000}})   # 3 x budget_exceeded
        e.authorize(carol["token"], "read", "hr.salary", "e-1")                                # policy_error: the forbid reads resource.frozen
        e.authorize(wide["token"], "create", "billing.refund", "o-9", context={"spend": {"currency": "EUR", "amount": 15000}})             # held
        for _ in range(5):
            e.authorize("garbage", "read", "crm.customer", "c-1")                              # 5 x token_invalid
        e.revoke_user("bob", by="hr")
        for _ in range(3):
            e.authorize(bob["token"], "read", "crm.customer", "c-1")                           # 3 x token_revoked for bob

        s = self.session("--ops")
        _, a = s.tool("anomalies")
        self.assertEqual(a["window"]["decisions"], 19)
        self.assertEqual(a["by_rule"], {"DELEGATE-APPROVAL-REQUIRED": 1, "DELEGATE-BUDGET-EXCEEDED": 3, "DELEGATE-CAPABILITY-RESOURCE": 5,
                                        "DELEGATE-POLICY-ERROR": 1, "DELEGATE-POLICY-PERMIT": 1, "DELEGATE-TOKEN-INVALID": 5, "DELEGATE-TOKEN-REVOKED": 3})
        self.assertEqual(a["events"]["user_revoked"], 1)
        self.assertEqual(a["denials_by_user"], {"None": 5, "alice": 9, "bob": 3, "carol": 1})
        self.assertEqual(a["denials_by_agent"], {"?": 5, "support-bot": 13})
        found = {f["code"]: f for f in a["findings"]}
        self.assertEqual(sorted(found), ["budget_exhausted", "capability_probing", "invalid_tokens", "policy_error", "revoked_token_in_use"])
        self.assertEqual((found["capability_probing"]["subject"], found["capability_probing"]["count"]), ("support-bot", 5))
        self.assertEqual((found["revoked_token_in_use"]["subject"], found["revoked_token_in_use"]["severity"]), ("bob", "high"))
        self.assertEqual((found["budget_exhausted"]["subject"], found["budget_exhausted"]["count"]), (alice["token_id"], 3))
        self.assertIn("not written to the audit log", a["issuance_refusals"]["note"])

        # thresholds are arguments: a backlog of one, a stricter revocation rule; a deny rate needs min_decisions
        _, b = s.tool("anomalies", thresholds={"pending_approvals": 1, "user_revocations": 1, "min_decisions": 10, "capability_denies_per_agent": 6})
        codes = [f["code"] for f in b["findings"]]
        for code in ("approval_backlog", "user_revocations", "deny_rate"):
            self.assertIn(code, codes)
        self.assertNotIn("capability_probing", codes)
        self.assertEqual(s.tool("anomalies", n=3)[1]["window"]["records"], 3)
        for bad in ({"thresholds": {"no_such_threshold": 1}}, {"thresholds": {"invalid_tokens": -1}}, {"thresholds": {"invalid_tokens": "5"}}, {"thresholds": [1]}, {"n": 0}):
            self.assertEqual(s.code("anomalies", **bad), -32602, bad)

        # refused token requests are not in the audit log; the server counts the ones it refused itself
        for _ in range(5):
            self.assertEqual(s.code("narrow", token=alice["token"], actor="summarizer", capability={"actions": ["read"], "resources": ["*"]}), "widening")
        _, c = s.tool("anomalies")
        self.assertEqual(c["issuance_refusals"]["counts"], {"DELEGATE-WIDENING": 5})
        self.assertIn("issuance_refusals", [f["code"] for f in c["findings"]])
        self.assertEqual(c["window"]["records"], a["window"]["records"])

    def test_privileged_tools_are_attributed_and_audited(self):
        e = self.engine()
        alice = e.issue_token("support-bot", user="alice", role="support-agent", task="ticket-7")
        wide = e.issue_token("support-bot", {"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 20000}}, user="alice")
        held = e.authorize(wide["token"], "create", "billing.refund", "o-9", context={"spend": {"currency": "EUR", "amount": 15000}})
        aid = held["approval"]["id"]
        s = self.session("--ops", "--admin", "--allow-tools", "approve,revoke_user,reload,delegate")

        # `by` is required, and a misspelt argument is refused before anything happens
        self.assertEqual(s.code("approve", approval_id=aid), -32602)
        self.assertEqual(s.code("revoke_user", user="alice"), -32602)
        self.assertEqual(s.code("revoke_user", user="alice", by=""), -32602)
        self.assertEqual(s.code("revoke_user", usr="alice", by="jane"), -32602)
        self.assertEqual(s.code("reload"), -32602)
        self.assertTrue(e.inspect_token(alice["token"])["valid"])

        # approve: the engine's own rules decide who may
        self.assertEqual(s.code("approve", approval_id=aid, by="alice"), "self_approval")
        self.assertEqual(s.code("approve", approval_id=aid, by="carol"), "approval_denied")
        self.assertEqual(s.code("approve", approval_id="no-such", by="bob"), "unknown_approval")
        is_error, out = s.tool("approve", approval_id=aid, by="bob")
        self.assertEqual((is_error, out["approved"], out["by"]), (False, aid, "bob"))
        self.assertEqual(e.authorize(wide["token"], "create", "billing.refund", "o-9", context={"spend": {"currency": "EUR", "amount": 15000}})["effect"], "allow")

        is_error, out = s.tool("revoke_user", user="alice", by="jane.doe")
        self.assertEqual((is_error, out["revoked_user"], out["by"]), (False, "alice", "jane.doe"))
        self.assertEqual(e.inspect_token(alice["token"])["reason"], "token_revoked")

        is_error, out = s.tool("reload", by="jane.doe")
        self.assertEqual((is_error, out["reloaded"], out["policy_version"], out["by"]), (False, True, e.info()["policy_version"], "jane.doe"))
        is_error, grant = s.tool("delegate", user="bob", agent="support-bot", role="support-agent", task="t-2", by="token-service")
        self.assertFalse(is_error, grant)

        events = [(r["event"], r.get("by")) for r in s.tool("audit_tail", n=6)[1]["records"]]
        self.assertEqual(events[-5:], [("approval_granted", "bob"), ("decision", None), ("user_revoked", "jane.doe"), ("bundle_reloaded", None), ("token_issued", None)])
        code, stderr = s.close()
        self.assertEqual(code, 0)
        self.assertIn("reload policy_version=" + out["policy_version"] + " by=jane.doe", stderr)        # the engine's reload record holds no `by`
        self.assertIn(f"delegate user=bob agent=support-bot role=support-agent token_id={grant['token_id']} by=token-service", stderr)
        self.assertNotIn(grant["token"], stderr)

    def test_a_governed_server_binds_the_operator_role(self):
        bundle = merged_bundle(self.tmp / "bundle")
        e = self.engine(bundle)
        operator = e.issue_token("smartdelegate-operator", user="olivia", role="sd-operator", task="ops-daily")
        integrator = e.issue_token("smartdelegate-integrator", user="ian", role="sd-integrator", task="integrate-crm")
        alice = e.issue_token("support-bot", user="alice", role="support-agent", task="ticket-7")
        wide = e.issue_token("support-bot", {"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 20000}}, user="alice")
        aid = e.authorize(wide["token"], "create", "billing.refund", "o-9", context={"spend": {"currency": "EUR", "amount": 15000}})["approval"]["id"]
        # the server exposes every privileged tool: only the token stands between the caller and them
        s = self.session("--ops", "--govern", "--admin", "--allow-tools", "approve,revoke_user,reload,delegate", bundle=bundle)
        op = operator["token"]

        for tool in MONITORING:
            is_error, out = s.tool(tool, token=op)
            self.assertFalse(is_error, (tool, out))
        self.assertEqual(s.tool("status", token=op)[1]["server"]["govern"], True)
        # each governed call is a decision in the audit log, with the human, the agent and the role
        d = [r for r in e.call("audit_tail", {"n": 50})["records"] if r["event"] == "decision" and r["resource"].startswith("smartdelegate.ops/")]
        self.assertEqual([r["resource"].split("/")[1] for r in d], MONITORING + ["status"])
        self.assertEqual({(r["user"], tuple(r["chain"]), r["role"], r["task"], r["action"], r["effect"]) for r in d},
                         {("olivia", ("smartdelegate-operator",), "sd-operator", "ops-daily", "read", "allow")})

        # the operator cannot approve, revoke users, reload (change the policy in force) or issue tokens
        before = e.call("audit_verify", {})["records"]
        for tool, args in (("approve", {"approval_id": aid}), ("approve", {"approval_id": aid, "by": "bob"}), ("revoke_user", {"user": "alice"}),
                           ("reload", {}), ("delegate", {"user": "bob", "agent": "support-bot", "role": "supervisor", "task": "escalation-1"})):
            is_error, out = s.tool(tool, token=op, **args)
            self.assertEqual((is_error, out["error"]["code"], out["error"]["rule"]), (True, "capability_action", "DELEGATE-CAPABILITY-ACTION"), tool)
        self.assertTrue(e.inspect_token(alice["token"])["valid"])
        self.assertIn(aid, e.call("approvals", {})["pending"])
        after = e.call("audit_tail", {"n": 50})["records"][before:]
        self.assertEqual([(r["event"], r["effect"], r["action"]) for r in after], [("decision", "deny", "operate")] * 5)     # refused, and on record
        self.assertEqual({r["user"] for r in after}, {"olivia"})

        # other tokens: the integrator reads status only; a business token reads nothing here; no token, nothing
        self.assertFalse(s.tool("status", token=integrator["token"])[0])
        self.assertEqual(s.code("audit_tail", token=integrator["token"]), "capability_resource")
        self.assertEqual(s.code("revoke_user", token=integrator["token"], user="alice"), "capability_action")
        self.assertEqual(s.code("status", token=alice["token"]), "capability_resource")
        self.assertEqual(s.code("status"), "token_invalid")
        self.assertEqual(s.code("status", token="garbage"), "token_invalid")
        e.revoke(operator["token_id"])
        self.assertEqual(s.code("status", token=op), "token_revoked")
        # the question tools are not governed: they act on a token the caller holds
        self.assertEqual(s.tool("whoami", token=integrator["token"])[1]["role"], "sd-integrator")

    def test_governed_attribution_and_a_bundle_without_the_ops_resource(self):
        # a role that may operate one tool: written here, by hand, as an adopter would write and review it
        bundle = merged_bundle(self.tmp / "bundle")
        roles = json.loads((bundle / "roles.json").read_text(encoding="utf-8"))
        roles["roles"]["sd-offboarder"] = {"members": [{"type": "Group", "id": "supervisors"}], "max_ttl": 300, "agents": ["support-bot"],
                                           "cap": {"actions": ["operate"], "resources": ["smartdelegate.ops/revoke_user"]}}
        (bundle / "roles.json").write_text(json.dumps(roles, indent=2), encoding="utf-8")
        policies = json.loads((bundle / "policies.json").read_text(encoding="utf-8"))
        policies["policies"]["test-offboarder-revokes"] = {
            "effect": "permit", "principal": {"op": "==", "entity": {"type": "Agent", "id": "support-bot"}},
            "action": {"op": "==", "entity": {"type": "Action", "id": "operate"}},
            "resource": {"op": "==", "entity": {"type": "SmartDelegateOps", "id": "revoke_user"}}, "conditions": [], "annotations": {"id": "test-offboarder-revokes"}}
        shutil.rmtree(bundle / "policies")           # this throwaway bundle has no sources: the permit above is test data, not a compiled policy
        policies["sources"] = {}
        (bundle / "policies.json").write_text(json.dumps(policies), encoding="utf-8")
        e = self.engine(bundle)
        bob = e.issue_token("support-bot", user="bob", role="sd-offboarder", task="offboard-alice")
        alice = e.issue_token("support-bot", user="alice", role="support-agent", task="ticket-7")
        s = self.session("--govern", "--admin", "--allow-tools", "revoke_user,reload", bundle=bundle)
        self.assertEqual(s.code("revoke_user", token=bob["token"], user="alice", by="someone-else"), "invalid_input")      # `by` is the token's user
        self.assertTrue(e.inspect_token(alice["token"])["valid"])
        is_error, out = s.tool("revoke_user", token=bob["token"], user="alice")
        self.assertEqual((is_error, out["by"]), (False, "bob"))
        self.assertEqual(s.code("reload", token=bob["token"]), "capability_resource")
        tail = e.call("audit_tail", {"n": 3})["records"]
        self.assertEqual([(r["event"], r.get("user"), r.get("by"), r.get("effect")) for r in tail],
                         [("decision", "bob", None, "allow"), ("user_revoked", "alice", "bob", None), ("decision", "bob", None, "deny")])
        self.assertEqual(e.inspect_token(alice["token"])["reason"], "token_revoked")
        s.close()

        plain = Session(BUNDLE, self.tmp / "plain-state", "--ops", "--govern")           # the conformance bundle has no smartdelegate.ops resource
        self.sessions.append(plain)
        with Engine({"bundle_dir": str(BUNDLE), "state_dir": str(self.tmp / "plain-state")}) as p:
            t = p.issue_token("support-bot", user="alice", role="support-agent", task="t")
        self.assertEqual(plain.code("status", token=t["token"]), "unknown_resource")
        code, stderr = plain.close()
        self.assertIn("--govern needs the resource 'smartdelegate.ops'", stderr)


# ---- AGENTS.md, llms.txt, the guides, the IAIso map -------------------------------

def links(path: Path) -> list:
    """Relative link targets of a Markdown file, resolved against its folder."""
    text = path.read_text(encoding="utf-8")
    return [(target, (path.parent / target.split("#")[0]).resolve()) for target in re.findall(r"\]\(([^)\s]+)\)", text)
            if not target.startswith(("http://", "https://", "mailto:", "#"))]


class Documents(unittest.TestCase):
    def test_relative_links_resolve(self):
        files = [ROOT / "AGENTS.md", ROOT / "llms.txt", ROOT / "docs" / "INTEGRATE.md", ROOT / "docs" / "FRAMEWORK.md", ROOT / "interfaces" / "README.md",
                 ROOT / "integrations" / "mcp" / "README.md", FRAGMENT / "README.md", *sorted((ROOT / "interfaces" / "docs").glob("*.md")),
                 *sorted(SKILLS.glob("*/SKILL.md")), *sorted(AGENTS.glob("*.md"))]
        self.assertGreaterEqual(len(files), 24)
        for f in files:
            for target, resolved in links(f):
                self.assertTrue(resolved.exists(), f"{f.relative_to(ROOT)}: link {target} does not resolve")

    def test_paths_named_in_backticks_exist(self):
        """`spec/API.md`, `skills/x/SKILL.md` ... in the agent-facing files name real files."""
        pattern = re.compile(r"`((?:spec|docs|src|tests|ports|interfaces|integrations|skills|agents|examples)/[A-Za-z0-9_./-]+?\.(?:md|py|json|yaml|sh|cedar))`")
        for f in [ROOT / "AGENTS.md", ROOT / "docs" / "INTEGRATE.md", ROOT / "docs" / "FRAMEWORK.md", ROOT / "interfaces" / "README.md", FRAGMENT / "README.md",
                  *sorted(SKILLS.glob("*/SKILL.md")), *sorted(AGENTS.glob("*.md")), *sorted((ROOT / "interfaces" / "docs").glob("*.md"))]:
            for rel in pattern.findall(f.read_text(encoding="utf-8")):
                self.assertTrue((ROOT / rel).exists() or (f.parent / rel).exists(), f"{f.relative_to(ROOT)} names `{rel}`, which does not exist")

    def test_agents_md(self):
        text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for rule in ("Never weaken a conformance vector", "The reference is `src/`", "Byte formats match exactly", "Policies are compiled by the Rust port",
                     "No secrets, keys or state in the repository", "Fail closed"):
            self.assertIn(rule, text)
        for command in ("cd tests && python3 -m unittest", "ports/conformance/run.sh", "./bootstrap.sh", "bootstrap.ps1", "python -m harness run"):
            self.assertIn(command, text)
        for path in ("bootstrap.sh", "bootstrap.ps1", "ports/conformance/run.sh", "ports/conformance/matrix.py", "skills/validate.py"):
            self.assertTrue((ROOT / path).exists(), path)
        self.assertNotIn("harness/", text.replace("`harness/`, `live/`, `scripts/`, `docker/`", ""))        # no harness internals

    def test_llms_txt(self):
        text = (ROOT / "llms.txt").read_text(encoding="utf-8")
        lines = text.split("\n")
        self.assertEqual(lines[0], "# SmartDelegate")
        self.assertTrue(lines[2].startswith("> "))
        self.assertLess(len(text), 8000)
        targets = [t for t, _ in links(ROOT / "llms.txt")]
        for needed in ("README.md", "spec/API.md", "spec/ROLES.md", "docs/INTEGRATE.md", "docs/FRAMEWORK.md", "docs/BRIDGES.md", "docs/LIMITATIONS.md", "AGENTS.md"):
            self.assertIn(needed, targets)
        self.assertEqual(sorted(t.split("/")[1] for t in targets if t.startswith("skills/")), EXPECTED_SKILLS)
        self.assertEqual(sorted(re.findall(r"^## (.+)$", text, re.M)), ["For agents", "Governance", "Integrate", "Optional", "Specification", "Start"])

    def test_the_python_in_the_integration_guide_runs(self):
        text = (ROOT / "docs" / "INTEGRATE.md").read_text(encoding="utf-8")
        blocks = re.findall(r"```python\n(.*?)```", text, re.S)
        self.assertEqual(len(blocks), 5)
        expected = ["alice support-agent {'EUR': 10000}", "{'id': 'c-1', 'name': 'Ada Lovelace', 'region': 'EU'}\nTrue",
                    "{'id': 'c-1', 'name': 'Ada Lovelace', 'region': 'EU'}\nFalse DELEGATE-BUDGET-EXCEEDED",
                    "DELEGATE-APPROVAL-REQUIRED\nTrue\nDELEGATE-POLICY-PERMIT\n4", "{'id': 'c-1', 'name': 'Ada Lovelace', 'region': 'EU'}"]
        for block, want in zip(blocks, expected):
            r = run(sys.executable, "-c", block)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, want), r.stderr)
        for heading in ("## Track A: connect your IAM", "## Track B: connect your agent system", "## Minimum viable integration", "## Before you call it enforced"):
            self.assertIn(heading, text)
        self.assertGreaterEqual(text.count("- [ ] "), 15)
        minimum = blocks[-1].strip().split("\n")
        self.assertLessEqual(len([line for line in minimum if line.strip()]), 10)
        for command in re.findall(r"^(?:[A-Z_]+=\S+ )*smartdelegate [^\n#]+", text, re.M):         # the guide's CLI lines are real commands too
            commands, options = skill_validator.cli_surface()
            self.assertEqual(skill_validator.check_command(command.strip(), commands, options), [], command)

    def test_interface_count_in_the_readme(self):
        from interfaces import contract
        text = (ROOT / "interfaces" / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"{len(contract.CHECKS)} checks", text)
        for name in contract.FACTORY_ARGUMENTS:
            self.assertIn(f"`--{name}`", text)

    def test_framework_document_and_iaiso_map_agree(self):
        text = (ROOT / "docs" / "FRAMEWORK.md").read_text(encoding="utf-8")
        doc = json.loads((ROOT / "spec" / "iaiso-map.json").read_text(encoding="utf-8"))
        smart = json.loads((ROOT / ".smart.json").read_text(encoding="utf-8"))
        # the keys the release process reads are untouched
        self.assertEqual((doc["version"], doc["iaiso_section"]), (smart["version"], smart["iaiso_section"]))
        self.assertEqual(list(doc)[:10], ["tool", "package", "version", "iaiso_section", "rule_prefix", "conforms_to", "cloud", "stacks_with", "controls", "starter_kits"])
        self.assertEqual(len(doc["controls"]), 8)
        fw = doc["framework"]
        self.assertEqual(tuple(fw["status_values"]), STATUSES)
        self.assertIs(fw["section_label"]["assigned_by_the_standard"], False)
        for concept, entry in fw["integration_status"].items():
            self.assertIn(entry["status"], STATUSES, concept)
        self.assertEqual(len(fw["principles"]), 9)
        for principle, entry in fw["principles"].items():
            self.assertIn(f"**{principle[0].upper()}{principle[1:]}**", text, principle)
            self.assertTrue(entry["where"] and entry["limit"], principle)

        # the mapping table: every row's status is one of the three values, and equals the map's
        section = text.split("### 3.3", 1)[1].split("### 3.4", 1)[0]
        rows = [[c.strip() for c in line.strip("|").split("|")] for line in section.split("\n") if line.startswith("| ") and "---" not in line][1:]
        self.assertEqual(len(rows), len(fw["integration_status"]))
        by_status = lambda s: next(v for v in STATUSES if s.startswith(v))
        self.assertEqual(sorted(by_status(r[3]) for r in rows), sorted(e["status"] for e in fw["integration_status"].values()))
        for hook in ("H1", "H2", "H3", "H4", "H5"):
            self.assertIn(f"**{hook}.", text)
            self.assertIn("not built", text.split(f"**{hook}.", 1)[0][-900:] + section)
        for sentence in ("No code in this repository calls SmartFabric", "It was not assigned\nby the standard", "The IAIso standard's own\nrepository was not consulted",
                         "Nothing here is a claim of certification"):
            self.assertIn(sentence, text)
        for framework in ("NIST AI 100-1", "ISO/IEC 42001:2023", "NIST SP 800-207", "LLM06:2025 Excessive Agency", "ASI03 Identity & Privilege Abuse"):
            self.assertIn(framework, text)
        self.assertNotRegex(text, r"(?i)\b(certified|compliant with|conforms to iso|conforms to nist)\b")

    def test_no_marketing_words_no_emoji(self):
        banned = re.compile(r"(?i)\b(seamless(ly)?|powerful|robust|cutting-edge|blazing|world-class|revolutionary|effortless(ly)?|best-in-class|game-chang\w+)\b")
        emoji = re.compile("[\U0001F300-\U0001FAFF☀-➿]")
        files = [ROOT / "AGENTS.md", ROOT / "llms.txt", ROOT / "docs" / "INTEGRATE.md", ROOT / "docs" / "FRAMEWORK.md", ROOT / "interfaces" / "README.md",
                 FRAGMENT / "README.md", *sorted((ROOT / "interfaces" / "docs").glob("*.md")), *sorted(SKILLS.glob("*/SKILL.md")), *sorted(AGENTS.glob("*.md"))]
        for f in files:
            text = f.read_text(encoding="utf-8")
            self.assertIsNone(banned.search(text), f"{f.name}: {banned.search(text)}")
            self.assertIsNone(emoji.search(text), f.name)


if __name__ == "__main__":
    unittest.main()
