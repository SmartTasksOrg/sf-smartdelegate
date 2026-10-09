"""integrations/ and site/: the adapter, the framework wrappers through their
framework-free path, the function-calling dispatcher, the MCP server over
stdio, the CI and pre-commit commands, and the playground's rule functions
against the engine.

    cd tests && python3 -m unittest test_integrations -v

LangChain, LlamaIndex, Node and bash are optional: a test that needs one that
is missing is skipped with the reason, never passed silently.
"""
import asyncio
import importlib.util
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import BUNDLE, CLI, ENV, EXAMPLES, FULL_CAP, PY, ROOT, Daemon, conformance_config

INTEGRATIONS = ROOT / "integrations"
SITE = ROOT / "site"
sys.path.insert(0, str(INTEGRATIONS))

import adapter as A  # noqa: E402
from sf_smartdelegate import DaemonClient, Engine, core  # noqa: E402
from sf_smartdelegate.backend import Backend, SmartDelegateError  # noqa: E402
from sf_smartdelegate.errors import EngineError  # noqa: E402
from sf_smartdelegate.guard import ApprovalRequired, Denied  # noqa: E402

T = 1700000000
NODE = shutil.which("node")
BASH = shutil.which("bash")
RULE = re.compile(r"^DELEGATE-[A-Z0-9]+(-[A-Z0-9]+)*$")

ADA = {"id": "c-1", "name": "Ada Lovelace", "email": "ada@example.com", "ssn": "123-45-6789", "region": "EU", "tier": "gold",
       "notes": "threatened to churn", "card": {"last4": "4242", "number": "4242424242424242"}}
BO = {"id": "c-2", "name": "Bo Diaz", "email": "bo@example.com", "ssn": "987-65-4321", "region": "US", "notes": ""}

READ = A.ToolSpec("read", "crm.customer", id="customer_id")
LIST = A.ToolSpec("read", "crm.customer")
UPDATE = A.ToolSpec("update", "crm.customer", id="customer_id", input="changes")
REFUND = A.ToolSpec("create", "billing.refund", id="order_id", spend=A.spend_from("currency", "amount"))
SALARY = A.ToolSpec("read", "hr.salary", id="employee")


def load(name: str, path: Path):
    """Import a file from a directory whose name is not a Python identifier."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def have(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


class FakeTools:
    """Stand-in tools that return more than an agent should see, and record
    whether they ran."""

    def __init__(self):
        self.calls = []

    def get_customer(self, customer_id):
        self.calls.append(("get_customer", customer_id))
        return dict(ADA)

    def get_customer_json(self, customer_id):
        self.calls.append(("get_customer_json", customer_id))
        return json.dumps(ADA)

    def list_customers(self):
        self.calls.append(("list_customers",))
        return [dict(ADA), dict(BO)]

    def export_report(self):
        self.calls.append(("export_report",))
        return "Ada Lovelace, ssn 123-45-6789"

    def update_customer(self, customer_id, changes):
        self.calls.append(("update_customer", customer_id, changes))
        return {**ADA, **changes}

    def refund(self, order_id, currency, amount):
        self.calls.append(("refund", order_id, amount))
        return {"order_id": order_id, "amount": amount, "currency": currency, "internal_note": "fraud score 0.2"}

    def read_salary(self, employee):
        self.calls.append(("read_salary", employee))
        return {"employee": employee, "amount": 100000}

    def broken(self, customer_id):
        raise RuntimeError("upstream said: ssn 123-45-6789 not found")


class EngineCase(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="smartdelegate-integrations-")
        self.engine = Engine(conformance_config(os.path.join(self.state, "state")))
        self.tools = FakeTools()
        self.addCleanup(shutil.rmtree, self.state, True)
        self.addCleanup(self.engine.close)

    def role_adapter(self, user="alice", role="support-agent", task="ticket-7", **kw):
        grant = A.delegate_for_task(self.engine, user=user, agent="support-bot", role=role, task=task, **kw)
        return A.Adapter(self.engine, grant), grant

    def cap_adapter(self, cap=None, user="alice"):
        grant = core.delegate(self.engine, user=user, agent="support-bot", capability=cap or FULL_CAP)
        return A.Adapter(self.engine, grant.token), grant


# ---- 1. adapter --------------------------------------------------------------

class AdapterTest(EngineCase):
    def test_allowed_call_runs_and_the_output_is_masked(self):
        ad, _ = self.role_adapter()
        out = ad.call(READ, self.tools.get_customer, {"customer_id": "c-1"})
        self.assertEqual(self.tools.calls, [("get_customer", "c-1")])
        self.assertEqual(out["name"], "Ada Lovelace")
        for hidden in ("ssn", "notes"):
            self.assertNotIn(hidden, out)
        self.assertEqual(out["card"], {"last4": "4242", "number": "[REDACTED]"})

    def test_json_text_output_is_masked_and_stays_json_text(self):
        ad, _ = self.role_adapter()
        out = ad.call(READ, self.tools.get_customer_json, {"customer_id": "c-1"})
        self.assertIsInstance(out, str)
        self.assertNotIn("123-45-6789", out)
        self.assertEqual(json.loads(out)["email"], "ada@example.com")

    def test_output_without_field_identity_is_withheld_unless_raw(self):
        ad, _ = self.role_adapter()
        self.assertEqual(ad.call(LIST, self.tools.export_report), A.WITHHELD)
        self.assertEqual(ad.call(LIST, lambda: 42), A.WITHHELD)
        self.assertIsNone(ad.call(LIST, lambda: None))
        raw = A.ToolSpec("read", "crm.customer", output="raw")
        self.assertEqual(ad.call(raw, lambda: "done"), "done")

    def test_list_output_gets_the_row_filter(self):
        ad, _ = self.role_adapter()
        rows = ad.call(LIST, self.tools.list_customers)
        self.assertEqual([r["id"] for r in rows], ["c-1"])     # alice is EU; the US row is dropped
        self.assertNotIn("ssn", rows[0])

    def test_denied_call_does_not_run_the_tool(self):
        ad, _ = self.role_adapter()
        with self.assertRaises(Denied) as cm:
            ad.call(SALARY, self.tools.read_salary, {"employee": "e-1"})
        self.assertEqual(self.tools.calls, [])
        d = A.Denial.of(cm.exception)
        self.assertEqual((d.reason, d.rule), ("capability_resource", "DELEGATE-CAPABILITY-RESOURCE"))
        self.assertIsNone(d.approval_id)
        self.assertTrue(d.decision_id.startswith("d-"))
        self.assertEqual(d.to_json()["error"]["by"], "smartdelegate")
        self.assertIn("DELEGATE-CAPABILITY-RESOURCE", d.text())

    def test_try_call_returns_the_denial(self):
        ad, _ = self.role_adapter()
        r = ad.try_call(SALARY, self.tools.read_salary, {"employee": "e-1"})
        self.assertFalse(r.ok)
        self.assertEqual(r.denial.rule, "DELEGATE-CAPABILITY-RESOURCE")
        ok = ad.try_call(READ, self.tools.get_customer, {"customer_id": "c-1"})
        self.assertTrue(ok.ok)
        self.assertIsNone(ok.denial)

    def test_input_is_checked_in_strict_mode(self):
        ad, _ = self.role_adapter()
        with self.assertRaises(Denied) as cm:
            ad.call(UPDATE, self.tools.update_customer, {"customer_id": "c-1", "changes": {"email": "new@example.com", "ssn": "000"}})
        self.assertEqual(cm.exception.reason, "field_denied")
        self.assertEqual(self.tools.calls, [])
        out = ad.call(UPDATE, self.tools.update_customer, {"customer_id": "c-1", "changes": {"email": "new@example.com"}})
        self.assertEqual(len(self.tools.calls), 1)
        self.assertEqual(out["email"], "new@example.com")     # the result is masked for "update": contact fields only
        for hidden in ("ssn", "name", "notes"):
            self.assertNotIn(hidden, out)

    def test_input_that_is_not_record_data_is_refused(self):
        ad, _ = self.role_adapter()
        r = ad.try_call(UPDATE, self.tools.update_customer, {"customer_id": "c-1", "changes": "email=x"})
        self.assertEqual((r.ok, r.denial.reason, r.denial.rule), (False, "invalid_arguments", "DELEGATE-INVALID-ARGUMENTS"))
        self.assertEqual(self.tools.calls, [])

    def test_spend_is_charged_to_the_token_budget(self):
        ad, _ = self.role_adapter()        # support-agent: 100.00 EUR per task
        out = ad.call(REFUND, self.tools.refund, {"order_id": "o-1", "currency": "EUR", "amount": 6000})
        self.assertEqual(out, {"order_id": "o-1", "amount": 6000, "currency": "EUR"})     # internal_note masked
        r = ad.try_call(REFUND, self.tools.refund, {"order_id": "o-2", "currency": "EUR", "amount": 6000})
        self.assertEqual(r.denial.rule, "DELEGATE-BUDGET-EXCEEDED")
        self.assertEqual(len(self.tools.calls), 1)

    def test_spend_must_be_a_currency_and_whole_minor_units(self):
        ad, _ = self.role_adapter()
        for args in ({"order_id": "o", "currency": "EUR", "amount": 60.5}, {"order_id": "o", "currency": "EUR", "amount": "6000"},
                     {"order_id": "o", "currency": "EUR", "amount": True}, {"order_id": "o", "currency": None, "amount": 1},
                     {"order_id": "o", "currency": "EUR", "amount": -1}, {"order_id": "o"}):
            r = ad.try_call(REFUND, self.tools.refund, args)
            self.assertEqual((r.ok, r.denial.reason), (False, "invalid_arguments"), args)
        self.assertEqual(self.tools.calls, [])

    def test_approval_required_carries_the_approval_id_and_a_retry_passes(self):
        ad, _ = self.cap_adapter()         # budget 200.00 EUR; over 100.00 needs a supervisor
        args = {"order_id": "o-9", "currency": "EUR", "amount": 15000}
        with self.assertRaises(ApprovalRequired) as cm:
            ad.call(REFUND, self.tools.refund, args)
        self.assertEqual(self.tools.calls, [])
        d = A.Denial.of(cm.exception)
        self.assertEqual((d.reason, d.rule), ("approval_required", "DELEGATE-APPROVAL-REQUIRED"))
        self.assertTrue(d.approval_id)
        self.assertEqual(d.to_json()["error"]["approval"], {"id": d.approval_id})
        self.assertIn(d.approval_id, d.text())
        self.engine.approve(d.approval_id, "bob")
        self.assertEqual(ad.call(REFUND, self.tools.refund, args)["order_id"], "o-9")
        self.assertEqual(len(self.tools.calls), 1)

    def test_no_token_expired_token_and_revoked_token_are_denials(self):
        holder = A.TaskToken()
        ad = A.Adapter(self.engine, holder)
        r = ad.try_call(READ, self.tools.get_customer, {"customer_id": "c-1"})
        self.assertEqual(r.denial.rule, "DELEGATE-TOKEN-INVALID")
        grant = A.delegate_for_task(self.engine, user="alice", agent="support-bot", role="support-agent", task="t")
        holder.set(grant)
        self.assertTrue(ad.try_call(READ, self.tools.get_customer, {"customer_id": "c-1"}).ok)
        self.engine.revoke(grant.token_id)
        r = ad.try_call(READ, self.tools.get_customer, {"customer_id": "c-1"})
        self.assertEqual(r.denial.rule, "DELEGATE-TOKEN-REVOKED")
        holder.clear()
        self.assertEqual(ad.try_call(READ, self.tools.get_customer, {"customer_id": "c-1"}).denial.reason, "token_invalid")
        self.assertEqual(len(self.tools.calls), 1)

    def test_token_is_read_on_every_call(self):
        current = {"token": ""}
        ad = A.Adapter(self.engine, lambda: current["token"])
        self.assertFalse(ad.try_call(READ, self.tools.get_customer, {"customer_id": "c-1"}).ok)
        current["token"] = A.delegate_for_task(self.engine, user="alice", agent="support-bot", role="support-agent", task="t").token
        self.assertTrue(ad.try_call(READ, self.tools.get_customer, {"customer_id": "c-1"}).ok)

    def test_a_backend_error_is_a_denial_and_the_tool_does_not_run(self):
        class Down(Backend):
            def call(self, op, payload):
                raise SmartDelegateError("daemon_unreachable", "connection refused")

        ad = A.Adapter(Down(), "any-token")
        r = ad.try_call(READ, self.tools.get_customer, {"customer_id": "c-1"})
        self.assertEqual((r.ok, r.denial.reason, r.denial.rule), (False, "daemon_unreachable", "DELEGATE-DAEMON-UNREACHABLE"))
        self.assertEqual(self.tools.calls, [])
        with self.assertRaises(TypeError):
            A.Adapter(object(), "t")

    def test_an_id_extractor_that_fails_is_a_denial(self):
        ad, _ = self.role_adapter()
        spec = A.ToolSpec("read", "crm.customer", id=lambda args: args["missing"])
        r = ad.try_call(spec, self.tools.get_customer, {"customer_id": "c-1"})
        self.assertEqual(r.denial.reason, "invalid_arguments")
        self.assertEqual(self.tools.calls, [])

    def test_wrap_binds_positional_arguments(self):
        ad, _ = self.role_adapter()
        seen = []
        spec = A.ToolSpec("read", "crm.customer", id=lambda args: seen.append(dict(args)) or args["customer_id"])
        get = ad.wrap(spec, self.tools.get_customer)
        self.assertNotIn("ssn", get("c-1"))
        self.assertEqual(seen, [{"customer_id": "c-1"}])
        self.assertEqual(get.__smartdelegate__, {"action": "read", "resource": "crm.customer"})
        text = ad.wrap(SALARY, self.tools.read_salary, on_deny="return")("e-1")
        self.assertTrue(text.startswith("Denied by SmartDelegate (capability_resource, DELEGATE-CAPABILITY-RESOURCE)"))
        with self.assertRaises(ValueError):
            ad.wrap(READ, self.tools.get_customer, on_deny="ignore")

    def test_async_tools(self):
        ad, _ = self.role_adapter()

        async def aget(customer_id):
            return dict(ADA)

        self.assertNotIn("ssn", asyncio.run(ad.acall(READ, aget, {"customer_id": "c-1"})))
        self.assertNotIn("ssn", asyncio.run(ad.awrap(READ, aget)("c-1")))
        with self.assertRaises(Denied):
            asyncio.run(ad.awrap(SALARY, aget)("e-1"))

    def test_delegate_for_task(self):
        grant = A.delegate_for_task(self.engine, user="alice", agent="support-bot", role="support-agent", task="ticket-7")
        self.assertEqual((grant.user, grant.chain, grant.role), ("alice", ["support-bot"], "support-agent"))
        self.assertEqual(grant.capability.budget, {"EUR": 10000})
        with self.assertRaises(EngineError) as cm:
            A.delegate_for_task(self.engine, user="dave", agent="support-bot", role="support-agent", task="ticket-7")
        self.assertEqual(cm.exception.code, "role_not_held")
        with self.assertRaises(EngineError) as cm:
            A.delegate_for_task(self.engine, user="alice", agent="support-bot", role="support-agent", task="t",
                                capability={"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 50000}})
        self.assertEqual(cm.exception.code, "role_exceeded")
        with self.assertRaises(ValueError):
            A.delegate_for_task(self.engine, user="alice", agent="support-bot", role="")

    def test_visible_tools_follow_the_capability(self):
        specs = {"get_customer": READ, "list_customers": LIST, "update_customer": UPDATE, "refund": REFUND, "read_salary": SALARY}
        ad, grant = self.role_adapter()
        self.assertEqual(ad.visible(specs), ["get_customer", "list_customers", "update_customer", "refund"])
        sub = core.narrow(self.engine, grant, actor="summarizer", ttl=60,
                          capability={"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["secret"]})
        narrow = A.Adapter(self.engine, sub)
        # the list tool asks for crm.customer/any, which the one-record capability does not cover
        self.assertEqual(narrow.visible(specs), ["get_customer"])
        self.assertEqual(A.Adapter(self.engine, None).visible(specs), [])
        self.assertEqual(A.Adapter(self.engine, "not-a-token").visible(specs), [])
        info = ad.whoami()
        self.assertEqual((info["valid"], info["user"], info["chain"]), (True, "alice", ["support-bot"]))

    def test_could_use_pattern_cases(self):
        from sf_smartdelegate.tokens import Cap
        cap = Cap(["re*"], ["crm.customer/c-*", "billing.refund/r-1", "hr.*"])
        self.assertTrue(A.could_use(cap, READ))
        self.assertTrue(A.could_use(cap, A.ToolSpec("read", "billing.refund", id="x")))
        self.assertTrue(A.could_use(cap, SALARY))
        self.assertFalse(A.could_use(cap, LIST))                                         # crm.customer/any
        self.assertFalse(A.could_use(cap, A.ToolSpec("create", "crm.customer", id="x")))  # action
        self.assertFalse(A.could_use(cap, A.ToolSpec("read", "crm.custom", id="x")))      # a different path
        self.assertFalse(A.could_use(Cap(["read"], ["crm.customer/"]), READ))

    def test_demo_runs(self):
        r = subprocess.run([sys.executable, str(INTEGRATIONS / "adapter.py"), "--demo"], capture_output=True, text=True, env=ENV)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertNotIn("ssn", out["read_customer"])
        self.assertEqual(out["refund_150_eur"]["error"]["rule"], "DELEGATE-BUDGET-EXCEEDED")


class AdapterOverDaemonTest(unittest.TestCase):
    """The same adapter with a DaemonClient: decisions over REST."""

    @classmethod
    def setUpClass(cls):
        cls.daemon = Daemon()
        cls.client = DaemonClient(cls.daemon.url, pep_key=Daemon.PEP, admin_key=Daemon.ADMIN)

    @classmethod
    def tearDownClass(cls):
        cls.daemon.close()

    def test_enforce_mask_and_deny_over_rest(self):
        tools = FakeTools()
        grant = A.delegate_for_task(self.client, user="alice", agent="support-bot", role="support-agent", task="ticket-7")
        ad = A.Adapter(DaemonClient(self.daemon.url, pep_key=Daemon.PEP), grant)      # the agent side holds no admin key
        out = ad.call(READ, tools.get_customer, {"customer_id": "c-1"})
        self.assertNotIn("ssn", out)
        r = ad.try_call(SALARY, tools.read_salary, {"employee": "e-1"})
        self.assertEqual(r.denial.rule, "DELEGATE-CAPABILITY-RESOURCE")
        self.assertEqual(ad.visible({"get_customer": READ, "read_salary": SALARY}), ["get_customer"])
        self.assertEqual(tools.calls, [("get_customer", "c-1")])

    def test_unreachable_daemon_is_a_denial(self):
        tools = FakeTools()
        ad = A.Adapter(DaemonClient("http://127.0.0.1:1", pep_key="x" * 20, timeout=2), "some-token")
        r = ad.try_call(READ, tools.get_customer, {"customer_id": "c-1"})
        self.assertEqual((r.ok, r.denial.reason), (False, "daemon_unreachable"))
        self.assertEqual(tools.calls, [])


# ---- 2 and 3. LangChain and LlamaIndex ------------------------------------------

class WrapperCase(EngineCase):
    MODULE: Path
    FRAMEWORK: str

    def setUp(self):
        super().setUp()
        self.mod = load("sd_" + self.FRAMEWORK.split(".")[0], self.MODULE)
        self.adapter, self.grant = self.role_adapter()

    def _framework_free(self):
        m = self.mod
        out = m.guarded_call(self.adapter, READ, self.tools.get_customer, kwargs={"customer_id": "c-1"})
        self.assertNotIn("ssn", out)
        self.assertEqual(m.guarded_call(self.adapter, READ, self.tools.get_customer, args=("c-1",))["id"], "c-1")
        text = m.guarded_call(self.adapter, SALARY, self.tools.read_salary, kwargs={"employee": "e-1"})
        self.assertIn("DELEGATE-CAPABILITY-RESOURCE", text)
        with self.assertRaises(Denied):
            m.guarded_call(self.adapter, SALARY, self.tools.read_salary, kwargs={"employee": "e-1"}, on_deny="raise")
        self.assertEqual([c[0] for c in self.tools.calls], ["get_customer", "get_customer"])

        async def aget(customer_id):
            return dict(ADA)

        self.assertNotIn("ssn", asyncio.run(m.guarded_acall(self.adapter, READ, aget, kwargs={"customer_id": "c-1"})))
        self.assertIn("DELEGATE-", asyncio.run(m.guarded_acall(self.adapter, SALARY, aget, kwargs={"employee": "e"})))

    def _clear_error_without_the_framework(self, package: str):
        with self.assertRaises(ImportError) as cm:
            self.mod.guard_tool(object(), READ, self.adapter)
        self.assertIn("pip install " + package, str(cm.exception))


class LangChainTest(WrapperCase):
    MODULE = INTEGRATIONS / "langchain" / "tool.py"
    FRAMEWORK = "langchain_core"

    def test_framework_free_path(self):
        self._framework_free()

    @unittest.skipIf(have("langchain_core"), "langchain_core is installed, so the missing-framework error cannot be shown")
    def test_missing_framework_gives_a_clear_error(self):
        self._clear_error_without_the_framework("langchain-core")

    @unittest.skipUnless(have("langchain_core"), "langchain_core is not installed: the guard_tool wrapper itself is not exercised")
    def test_real_langchain_tools(self):
        from langchain_core.tools import BaseTool, StructuredTool, Tool
        tools, m, ad = self.tools, self.mod, self.adapter

        def get_customer(customer_id: str) -> dict:
            """Fetch a customer."""
            return tools.get_customer(customer_id)

        async def aget_customer(customer_id: str) -> dict:
            """Fetch a customer."""
            return tools.get_customer(customer_id)

        def read_salary(employee: str) -> dict:
            """Read a salary."""
            return tools.read_salary(employee)

        original = StructuredTool.from_function(func=get_customer, coroutine=aget_customer)
        safe = m.guard_tool(original, READ, ad)
        self.assertEqual((safe.name, safe.description, safe.args), (original.name, original.description, original.args))
        self.assertNotIn("ssn", safe.invoke({"customer_id": "c-1"}))
        self.assertNotIn("ssn", asyncio.run(safe.ainvoke({"customer_id": "c-1"})))
        self.assertIn("ssn", original.invoke({"customer_id": "c-1"}))       # the original is left as it was
        message = safe.invoke({"name": "get_customer", "args": {"customer_id": "c-1"}, "id": "call-1", "type": "tool_call"})
        self.assertNotIn("123-45-6789", str(message.content))

        salary = StructuredTool.from_function(func=read_salary)
        self.assertIn("DELEGATE-CAPABILITY-RESOURCE", m.guard_tool(salary, SALARY, ad).invoke({"employee": "e-1"}))
        with self.assertRaises(Denied):
            m.guard_tool(salary, SALARY, ad, on_deny="raise").invoke({"employee": "e-1"})
        self.assertNotIn(("read_salary", "e-1"), tools.calls)

        single = Tool(name="lookup", description="Look a customer up", func=lambda q: json.dumps(ADA))
        self.assertNotIn("123-45-6789", m.guard_tool(single, LIST, ad).invoke("ada"))

        class Custom(BaseTool):
            name: str = "custom"
            description: str = "A BaseTool subclass"

            def _run(self, customer_id: str) -> dict:
                return dict(ADA)

        custom = m.guard_tool(Custom(), READ, ad)
        self.assertEqual(custom.args, Custom().args)
        self.assertNotIn("ssn", custom.invoke({"customer_id": "c-1"}))

        specs = {"get_customer": READ, "read_salary": SALARY}
        self.assertEqual([t.name for t in m.guard_tools([original, salary], specs, ad, only_usable=True)], ["get_customer"])
        with self.assertRaises(KeyError):
            m.guard_tools([original, salary], {"get_customer": READ}, ad)


class LlamaIndexTest(WrapperCase):
    MODULE = INTEGRATIONS / "llamaindex" / "tool.py"
    FRAMEWORK = "llama_index"

    def test_framework_free_path(self):
        self._framework_free()

    @unittest.skipIf(have("llama_index"), "llama_index is installed, so the missing-framework error cannot be shown")
    def test_missing_framework_gives_a_clear_error(self):
        self._clear_error_without_the_framework("llama-index-core")

    @unittest.skipUnless(have("llama_index"), "llama_index is not installed: the guard_tool wrapper itself is not exercised")
    def test_real_llamaindex_tools(self):
        from llama_index.core.tools import FunctionTool
        tools, m, ad = self.tools, self.mod, self.adapter

        def get_customer(customer_id: str) -> dict:
            """Fetch a customer."""
            return tools.get_customer(customer_id)

        async def aget_customer(customer_id: str) -> dict:
            """Fetch a customer."""
            return tools.get_customer(customer_id)

        def read_salary(employee: str) -> dict:
            """Read a salary."""
            return tools.read_salary(employee)

        original = FunctionTool.from_defaults(fn=get_customer)
        safe = m.guard_tool(original, READ, ad)
        self.assertIs(safe.metadata, original.metadata)
        self.assertNotIn("ssn", safe.call(customer_id="c-1").raw_output)
        self.assertNotIn("ssn", safe.call("c-1").raw_output)
        self.assertNotIn("123-45-6789", safe.call(customer_id="c-1").content)
        self.assertNotIn("ssn", asyncio.run(safe.acall(customer_id="c-1")).raw_output)
        self.assertIn("ssn", original.call(customer_id="c-1").raw_output)

        async_only = FunctionTool.from_defaults(async_fn=aget_customer, name="aget_customer")
        self.assertNotIn("ssn", m.guard_tool(async_only, READ, ad).call(customer_id="c-1").raw_output)

        salary = FunctionTool.from_defaults(fn=read_salary)
        self.assertIn("DELEGATE-CAPABILITY-RESOURCE", m.guard_tool(salary, SALARY, ad).call(employee="e-1").raw_output)
        with self.assertRaises(Denied):
            m.guard_tool(salary, SALARY, ad, on_deny="raise").call(employee="e-1")
        self.assertNotIn(("read_salary", "e-1"), tools.calls)

        specs = {"get_customer": READ, "read_salary": SALARY}
        self.assertEqual([t.metadata.name for t in m.guard_tools([original, salary], specs, ad, only_usable=True)], ["get_customer"])
        with self.assertRaises(KeyError):
            m.guard_tools([original, salary], {"get_customer": READ}, ad)


# ---- 4. function calling -----------------------------------------------------

class FunctionCallingTest(EngineCase):
    def setUp(self):
        super().setUp()
        self.fc = load("sd_function_calling", INTEGRATIONS / "function-calling" / "schema.py")
        t = self.tools
        self.table = {"get_customer": (t.get_customer, READ), "list_customers": (t.list_customers, LIST),
                      "export_report": (t.export_report, LIST), "update_customer": (t.update_customer, UPDATE),
                      "refund": (t.refund, REFUND), "read_salary": (t.read_salary, SALARY), "broken": (t.broken, READ)}

    def test_dispatch_enforces_and_masks(self):
        ad, _ = self.role_adapter()
        dispatch = self.fc.guard_dispatch(self.table, ad)
        out = json.loads(dispatch("get_customer", '{"customer_id": "c-1"}'))
        self.assertEqual(out["name"], "Ada Lovelace")
        self.assertNotIn("ssn", out)
        self.assertEqual(json.loads(dispatch("get_customer", {"customer_id": "c-1"}))["id"], "c-1")      # Anthropic passes an object
        self.assertEqual([r["id"] for r in json.loads(dispatch("list_customers", ""))], ["c-1"])
        self.assertEqual(json.loads(dispatch("export_report", "{}")), A.WITHHELD)

    def test_dispatch_returns_structured_denials(self):
        ad, _ = self.cap_adapter()
        dispatch = self.fc.guard_dispatch(self.table, ad)
        err = json.loads(dispatch("read_salary", '{"employee": "e-1"}'))["error"]
        self.assertEqual((err["code"], err["rule"], err["by"]), ("capability_resource", "DELEGATE-CAPABILITY-RESOURCE", "smartdelegate"))
        err = json.loads(dispatch("update_customer", json.dumps({"customer_id": "c-1", "changes": {"ssn": "0"}})))["error"]
        self.assertEqual(err["rule"], "DELEGATE-FIELD-DENIED")
        err = json.loads(dispatch("refund", json.dumps({"order_id": "o-1", "currency": "EUR", "amount": 15000})))["error"]
        self.assertEqual(err["rule"], "DELEGATE-APPROVAL-REQUIRED")
        self.assertTrue(err["approval"]["id"])
        self.assertEqual(self.tools.calls, [])
        self.engine.approve(err["approval"]["id"], "bob")
        ok = json.loads(dispatch("refund", json.dumps({"order_id": "o-1", "currency": "EUR", "amount": 15000})))
        self.assertEqual(ok, {"order_id": "o-1", "amount": 15000, "currency": "EUR"})

    def test_dispatch_refuses_what_it_cannot_map(self):
        ad, _ = self.role_adapter()
        dispatch = self.fc.guard_dispatch(self.table, ad)
        for name, arguments, code in (("drop_database", "{}", "unknown_tool"), ("get_customer", "{not json", "invalid_arguments"),
                                      ("get_customer", "[1, 2]", "invalid_arguments"), ("get_customer", '"c-1"', "invalid_arguments")):
            err = json.loads(dispatch(name, arguments))["error"]
            self.assertEqual(err["code"], code, (name, arguments))
            self.assertRegex(err["rule"], RULE)
        self.assertEqual(self.tools.calls, [])

    def test_a_failing_tool_does_not_leak_its_message(self):
        ad, _ = self.role_adapter()
        text = self.fc.guard_dispatch(self.table, ad)("broken", '{"customer_id": "c-1"}')
        self.assertEqual(json.loads(text)["error"]["code"], "tool_failed")
        self.assertNotIn("123-45-6789", text)

    def test_tool_list_is_filtered_to_what_the_capability_covers(self):
        openai = [{"type": "function", "function": {"name": n, "description": n, "parameters": {"type": "object"}}} for n in self.table]
        anthropic = [{"name": n, "description": n, "input_schema": {"type": "object"}} for n in self.table]
        unmapped = {"name": "drop_database", "input_schema": {"type": "object"}}
        ad, grant = self.role_adapter()
        names = lambda schemas: [self.fc.schema_name(s) for s in schemas]
        full = ["get_customer", "list_customers", "export_report", "update_customer", "refund", "broken"]
        self.assertEqual(names(self.fc.filter_tool_list(openai, self.table, ad)), full)
        self.assertEqual(names(self.fc.filter_tool_list(anthropic + [unmapped], self.table, ad)), full)
        self.assertEqual(self.fc.usable_tools(self.table, ad), full)

        auditor = A.Adapter(self.engine, A.delegate_for_task(self.engine, user="carol", agent="support-bot", role="auditor"))
        self.assertEqual(names(self.fc.filter_tool_list(openai, self.table, auditor)),
                         ["get_customer", "list_customers", "export_report", "update_customer", "broken"])
        sub = core.narrow(self.engine, grant, actor="refund-helper", ttl=60,
                          capability={"actions": ["create"], "resources": ["billing.refund/*"], "deny_labels": ["secret"], "budget": {"EUR": 1000}})
        self.assertEqual(names(self.fc.filter_tool_list(anthropic, self.table, A.Adapter(self.engine, sub))), ["refund"])
        self.assertEqual(self.fc.filter_tool_list(openai, self.table, A.Adapter(self.engine, None)), [])
        # hidden is not the enforcement: a call to a hidden tool is still decided
        err = json.loads(self.fc.guard_dispatch(self.table, A.Adapter(self.engine, sub))("get_customer", '{"customer_id": "c-1"}'))["error"]
        self.assertEqual(err["rule"], "DELEGATE-CAPABILITY-ACTION")


# ---- 5. MCP server -----------------------------------------------------------

class McpSession:
    def __init__(self, state: str, *extra: str, env: dict | None = None):
        self.proc = subprocess.Popen([sys.executable, str(INTEGRATIONS / "mcp" / "server.py"), "--bundle", str(BUNDLE), "--state", state, *extra],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                     bufsize=1, env={**ENV, **(env or {})})
        self.next_id = 0

    def raw(self, line: str) -> dict:
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        reply = self.proc.stdout.readline()
        if not reply:
            raise AssertionError("the MCP server exited: " + self.proc.stderr.read())
        return json.loads(reply)

    def notify(self, method: str) -> None:
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        reply = self.raw(json.dumps(msg))
        assert reply.get("id") == self.next_id and reply.get("jsonrpc") == "2.0", reply
        return reply

    def tool(self, name: str, arguments: dict | None = None) -> tuple:
        """-> (isError, structured result)"""
        r = self.request("tools/call", {"name": name, "arguments": arguments or {}})["result"]
        assert json.loads(r["content"][0]["text"]) == r["structuredContent"], r
        return r["isError"], r["structuredContent"]

    def close(self) -> int:
        self.proc.stdin.close()
        code = self.proc.wait(timeout=20)
        self.proc.stdout.close()
        self.proc.stderr.close()
        return code


class McpServerTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="smartdelegate-mcp-")
        self.state = os.path.join(self.dir, "state")
        self.sessions = []
        self.addCleanup(shutil.rmtree, self.dir, True)

    def tearDown(self):
        for s in self.sessions:
            if s.proc.poll() is None:
                s.proc.kill()
                s.proc.wait()
                for f in (s.proc.stdin, s.proc.stdout, s.proc.stderr):
                    f.close()

    def session(self, *extra: str, env: dict | None = None) -> McpSession:
        s = McpSession(self.state, *extra, env=env)
        self.sessions.append(s)
        return s

    def root_token(self) -> str:
        with Engine({"bundle_dir": str(BUNDLE), "state_dir": self.state}) as e:
            return A.delegate_for_task(e, user="alice", agent="support-bot", role="support-agent", task="ticket-7").token

    def test_handshake_and_tool_list(self):
        s = self.session()
        init = s.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})["result"]
        self.assertEqual(init["protocolVersion"], "2025-06-18")
        self.assertEqual(init["serverInfo"]["name"], "smartdelegate")
        self.assertIn("tools", init["capabilities"])
        s.notify("notifications/initialized")
        self.assertEqual(s.request("ping")["result"], {})
        old = s.request("initialize", {"protocolVersion": "1999-01-01"})["result"]
        self.assertIn(old["protocolVersion"], ("2025-06-18", "2025-03-26", "2024-11-05"))
        tools = s.request("tools/list")["result"]["tools"]
        self.assertEqual([t["name"] for t in tools], ["whoami", "roles", "check", "explain", "narrow"])
        for t in tools:
            self.assertEqual(t["inputSchema"]["type"], "object")
            self.assertTrue(t["description"])
        self.assertEqual(s.close(), 0)

    def test_delegate_is_refused_without_the_admin_flag(self):
        s = self.session()
        is_error, out = s.tool("delegate", {"user": "alice", "agent": "support-bot", "role": "support-agent", "task": "t-1"})
        self.assertTrue(is_error)
        self.assertEqual((out["error"]["code"], out["error"]["rule"]), ("admin_required", "DELEGATE-ADMIN-REQUIRED"))
        self.assertNotIn("token", out)

    def test_questions_about_a_token(self):
        token = self.root_token()
        s = self.session()
        is_error, who = s.tool("whoami", {"token": token})
        self.assertFalse(is_error)
        self.assertEqual((who["valid"], who["user"], who["chain"], who["role"], who["task"]), (True, "alice", ["support-bot"], "support-agent", "ticket-7"))
        self.assertEqual(who["cap"]["budget"], {"EUR": 10000})
        _, bad = s.tool("whoami", {"token": token[:-4] + "AAAA"})
        self.assertEqual((bad["valid"], bad["rule"]), (False, "DELEGATE-TOKEN-INVALID"))

        _, roles = s.tool("roles")
        by_name = {r["name"]: r for r in roles["roles"]}
        self.assertEqual(sorted(by_name), ["auditor", "break-glass", "supervisor", "support-agent"])
        self.assertEqual(by_name["supervisor"]["tasks"], ["escalation-*"])
        self.assertEqual(by_name["support-agent"]["ceiling"]["budget"], {"EUR": 10000})

        is_error, d = s.tool("check", {"token": token, "action": "read", "resource": "crm.customer", "id": "c-1", "data": ADA})
        self.assertFalse(is_error)
        self.assertEqual((d["effect"], d["rule"]), ("allow", "DELEGATE-POLICY-PERMIT"))
        self.assertNotIn("ssn", d["data"])
        is_error, d = s.tool("check", {"token": token, "action": "read", "resource": "hr.salary", "id": "e-1"})
        self.assertFalse(is_error)        # a deny is an answer, not an error
        self.assertEqual((d["effect"], d["rule"]), ("deny", "DELEGATE-CAPABILITY-RESOURCE"))

        # check is a dry run: asking twice about 60.00 EUR of a 100.00 EUR budget spends nothing
        spend = {"token": token, "action": "create", "resource": "billing.refund", "id": "o-1", "context": {"spend": {"currency": "EUR", "amount": 6000}}}
        self.assertEqual([s.tool("check", spend)[1]["effect"] for _ in range(3)], ["allow"] * 3)
        _, ex = s.tool("explain", spend)
        self.assertEqual(ex["effect"], "allow")
        self.assertTrue(any(step["check"] == "token" for step in ex["explain"]))
        s.close()
        with Engine({"bundle_dir": str(BUNDLE), "state_dir": self.state}) as e:
            events = [r.event for r in core.audit(e, 50)]
        self.assertEqual(events, ["token_issued"])       # no decision was logged

    def test_narrow_and_admin_delegate(self):
        s = self.session("--admin")
        self.assertEqual([t["name"] for t in s.request("tools/list")["result"]["tools"]][-1], "delegate")
        is_error, grant = s.tool("delegate", {"user": "bob", "agent": "support-bot", "role": "supervisor", "task": "escalation-1"})
        self.assertFalse(is_error, grant)
        self.assertEqual((grant["user"], grant["role"], grant["expires_in"]), ("bob", "supervisor", 300))
        for args, code in (({"user": "dave", "agent": "support-bot", "role": "support-agent", "task": "t"}, "role_not_held"),
                           ({"user": "bob", "agent": "support-bot", "role": "supervisor"}, "role_exceeded"),
                           ({"user": "alice", "agent": "support-bot", "role": "support-agent", "task": "t",
                             "capability": {"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 20000}}}, "role_exceeded")):
            is_error, out = s.tool("delegate", args)
            self.assertTrue(is_error)
            self.assertEqual(out["error"]["code"], code)
            self.assertRegex(out["error"]["rule"], RULE)

        is_error, sub = s.tool("narrow", {"token": grant["token"], "actor": "summarizer", "ttl": 60,
                                          "capability": {"actions": ["read"], "resources": ["crm.customer/c-1"]}})
        self.assertFalse(is_error, sub)
        self.assertEqual((sub["chain"], sub["role"], sub["expires_in"]), (["support-bot", "summarizer"], "supervisor", 60))
        self.assertEqual(s.tool("whoami", {"token": sub["token"]})[1]["chain"], ["support-bot", "summarizer"])
        is_error, out = s.tool("narrow", {"token": sub["token"], "actor": "summarizer", "capability": {"actions": ["read"], "resources": ["*"]}})
        self.assertTrue(is_error)
        self.assertEqual(out["error"]["rule"], "DELEGATE-WIDENING")

    def test_current_token_from_file_and_environment(self):
        token = self.root_token()
        path = os.path.join(self.dir, "token")
        Path(path).write_text(token + "\n", encoding="utf-8")
        s = self.session("--token-file", path)
        self.assertEqual(s.tool("whoami")[1]["user"], "alice")
        Path(path).write_text("", encoding="utf-8")       # re-read on every call
        is_error, out = s.tool("whoami")
        self.assertTrue(is_error)
        self.assertEqual(out["error"]["code"], "token_invalid")
        e = self.session(env={"SMARTDELEGATE_TOKEN": token})
        self.assertEqual(e.tool("check", {"action": "read", "resource": "crm.customer", "id": "c-1"})[1]["effect"], "allow")

    def test_malformed_requests_get_json_rpc_errors_and_the_server_survives(self):
        s = self.session()
        self.assertEqual(s.raw("{this is not json")["error"]["code"], -32700)
        self.assertEqual(s.raw("[]")["error"]["code"], -32600)
        self.assertEqual(s.raw('[{"jsonrpc": "2.0", "id": 1, "method": "ping"}]')["error"]["code"], -32600)
        self.assertEqual(s.raw('"ping"')["error"]["code"], -32600)
        self.assertEqual(s.raw('{"jsonrpc": "2.0", "id": 5}')["error"]["code"], -32600)
        self.assertEqual(s.raw('{"jsonrpc": "1.0", "id": 5, "method": "ping"}')["error"]["code"], -32600)
        self.assertEqual(s.raw('{"jsonrpc": "2.0", "id": {"a": 1}, "method": "ping"}')["error"]["code"], -32600)
        self.assertEqual(s.raw("[" * 100000)["error"]["code"], -32700)
        self.assertEqual(s.request("resources/list")["error"]["code"], -32601)
        self.assertEqual(s.raw('{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": [1]}')["error"]["code"], -32602)
        for params in ({"name": "drop_database", "arguments": {}}, {"name": "check", "arguments": "x"}, {"arguments": {}},
                       {"name": "check", "arguments": {"action": "read"}},                                        # resource missing
                       {"name": "check", "arguments": {"action": "read", "resource": "crm.customer", "resorce_id": "c-1"}},
                       {"name": "narrow", "arguments": {"actor": "summarizer", "token": "t", "ttl": "60"}}):
            self.assertEqual(s.request("tools/call", params)["error"]["code"], -32602, params)
        # an engine-level error is a tool result, not a protocol error
        is_error, out = s.tool("check", {"token": "garbage", "action": "read", "resource": "crm.customer", "context": {"iam": {}}})
        self.assertTrue(is_error)
        self.assertEqual(out["error"]["code"], "invalid_context")
        is_error, out = s.tool("whoami")
        self.assertTrue(is_error)
        self.assertEqual(out["error"]["code"], "token_invalid")
        s.notify("tools/call")                 # a notification gets no reply
        self.assertEqual(s.request("ping")["result"], {})
        self.assertEqual(s.close(), 0)

    def test_unknown_options_are_refused_at_startup(self):
        r = subprocess.run([sys.executable, str(INTEGRATIONS / "mcp" / "server.py"), "--bundle", str(BUNDLE), "--adminn", "x"],
                           capture_output=True, text=True, env=ENV, stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 1)
        self.assertIn("unknown option", r.stderr)


# ---- 6, 7, 8. CI action, pre-commit hooks, editor tasks, Flowise ----------------

def cli(*args: str, cwd=None) -> subprocess.CompletedProcess:
    return subprocess.run([*CLI, *args], capture_output=True, text=True, env=ENV, cwd=cwd)


def yaml_or_none():
    try:
        import yaml
        return yaml
    except ImportError:
        return None


class BundleCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="smartdelegate-ci-")
        self.bundle = os.path.join(self.dir, "bundle")
        shutil.copytree(BUNDLE, self.bundle)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def make_stale(self):
        with open(os.path.join(self.bundle, "policies", "crm.cedar"), "a", encoding="utf-8") as f:
            f.write("\n// edited without recompiling\n")


class PreCommitTest(BundleCase):
    FILE = ROOT / ".pre-commit-hooks.yaml"

    def hooks(self) -> list:
        text = self.FILE.read_text(encoding="utf-8")
        yaml = yaml_or_none()
        if yaml is not None:
            return yaml.safe_load(text)
        # no PyYAML: read the flat "key: value" structure the file uses
        hooks = []
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            m = re.match(r"^(- |  )([a-z_]+): (.*)$", line)
            self.assertIsNotNone(m, f"unexpected line in .pre-commit-hooks.yaml: {line!r}")
            if m.group(1) == "- ":
                hooks.append({})
            value = m.group(3)
            if value.startswith("["):
                value = [v.strip() for v in value.strip("[]").split(",")]
            elif value in ("true", "false"):
                value = value == "true"
            hooks[-1][m.group(2)] = value
        return hooks

    def test_hooks_file_is_well_formed(self):
        hooks = self.hooks()
        self.assertEqual([h["id"] for h in hooks], ["smartdelegate-policy-check", "smartdelegate-policy-test"])
        script = re.search(r"^sf-smartdelegate = \"(.+)\"$", (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
        self.assertIsNotNone(script, "pyproject.toml no longer defines the sf-smartdelegate console script")
        for h in hooks:
            self.assertEqual(h["language"], "python")
            self.assertIs(h["pass_filenames"], False)
            self.assertEqual(h["entry"].split()[0], "sf-smartdelegate")
            self.assertTrue(h["name"])
            files = re.compile(h["files"])
            for path in ("bundle/policies/crm.cedar", "bundle/policies.json", "bundle/roles.json", "bundle/tests/basics.json"):
                self.assertTrue(files.search(path), path)
            for path in ("src/app.py", "docs/bundle.md", "other/policies.json", "bundle/README.md"):
                self.assertFalse(files.search(path), path)

    def test_hook_commands_run_against_a_bundle(self):
        check, test = self.hooks()
        run = lambda h: cli(*h["entry"].split()[1:], *h["args"], cwd=self.dir)      # what pre-commit executes, from the repository root
        r = run(check)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("bundle loads", r.stdout)
        r = run(test)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r"\d+ tests, 0 failed")
        self.make_stale()
        r = run(check)
        self.assertEqual(r.returncode, 1)
        self.assertIn("bundle_stale", r.stderr)


class GithubActionTest(BundleCase):
    FILE = INTEGRATIONS / "github-action" / "action.yml"

    def setUp(self):
        super().setUp()
        self.text = self.FILE.read_text(encoding="utf-8")

    def steps(self) -> list:
        """[(name, env, script)] for each `run:` step."""
        yaml = yaml_or_none()
        if yaml is not None:
            doc = yaml.safe_load(self.text)
            self.assertEqual(doc["runs"]["using"], "composite")
            self.assertEqual(sorted(doc["inputs"]), ["bundle", "package", "public-key", "python-version"])
            self.assertTrue(doc["inputs"]["bundle"]["required"])
            for step in doc["runs"]["steps"]:
                if "run" in step:
                    self.assertEqual(step["shell"], "bash")       # composite run steps must name a shell
            return [(s.get("name", ""), s.get("env") or {}, s["run"]) for s in doc["runs"]["steps"] if "run" in s]
        steps = []
        for block in re.split(r"\n    - ", self.text.split("  steps:\n", 1)[1]):
            run = re.search(r"\n      run: (\|\n(?:        .*\n?)+|.*)", block)
            if not run:
                continue
            script = run.group(1)
            if script.startswith("|"):
                script = "\n".join(line[8:] for line in script.splitlines()[1:])
            env = dict(re.findall(r"\n        ([A-Z_]+): (.*)", block.split("\n      run:")[0]))
            name = re.search(r"name: (.*)", block)
            steps.append((name.group(1) if name else "", env, script))
        return steps

    def run_step(self, name_part: str, inputs: dict) -> subprocess.CompletedProcess:
        name, env, script = next(s for s in self.steps() if name_part in s[0])
        shim = os.path.join(self.dir, "bin")
        os.makedirs(shim, exist_ok=True)
        path = os.path.join(shim, "sf-smartdelegate")       # the console script the install step provides
        Path(path).write_text(f'#!/bin/sh\nexec "{sys.executable}" -m sf_smartdelegate "$@"\n', encoding="utf-8")
        os.chmod(path, 0o755)
        py = os.path.join(shim, "python")
        if not os.path.exists(py):
            os.symlink(sys.executable, py)
        resolved = {k: re.sub(r"\$\{\{\s*inputs\.([a-z-]+)\s*\}\}", lambda m: inputs.get(m.group(1), ""), v) for k, v in env.items()}
        return subprocess.run([BASH, "-e", "-o", "pipefail", "-c", script], capture_output=True, text=True, cwd=self.dir,
                              env={**ENV, **resolved, "PATH": shim + os.pathsep + ENV.get("PATH", "")})

    def test_action_file_is_sane(self):
        uses = re.findall(r"uses:\s*(\S+)", self.text)
        self.assertEqual(uses, ["actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"])   # nothing third-party, pinned by commit (v7.0.0)
        scripts = "\n".join(s[2] for s in self.steps())
        # inputs reach the shell through env, never by interpolation into the script
        self.assertNotIn("${{", scripts)
        commands = re.findall(r"^\s*sf-smartdelegate (.+)$", scripts, re.M)
        self.assertEqual(len(commands), 3)
        from sf_smartdelegate.cli import HELP
        for c in commands:
            words = c.split()
            self.assertIn(" ".join(words[:2]), ("policy check", "policy test"))
            self.assertIn(f"  {' '.join(words[:2])} ", HELP)
            for flag in (w for w in words if w.startswith("--")):
                self.assertIn(flag, ("--bundle", "--config"))
                self.assertIn(flag, HELP)
        self.assertIn("pip install", scripts)

    @unittest.skipUnless(BASH, "bash is not available: the action's run steps are not executed")
    def test_run_steps_pass_on_the_conformance_bundle_and_fail_on_a_stale_one(self):
        inputs = {"bundle": "bundle"}
        r = self.run_step("Policy check", inputs)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("bundle loads", r.stdout)
        r = self.run_step("Policy tests", inputs)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r"\d+ tests, 0 failed")
        self.make_stale()
        r = self.run_step("Policy check", inputs)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("bundle_stale", r.stderr)

    @unittest.skipUnless(BASH, "bash is not available: the action's run steps are not executed")
    def test_signature_step(self):
        key = os.path.join(self.dir, "ci")
        self.assertEqual(cli("bundle", "keygen", key).returncode, 0)
        public = Path(key + ".pub").read_text(encoding="utf-8")
        r = self.run_step("signature", {"bundle": "bundle", "public-key": public})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("bundle_unsigned", r.stderr)
        self.assertEqual(cli("bundle", "sign", "--key", key + ".key", "--bundle", self.bundle).returncode, 0)
        r = self.run_step("signature", {"bundle": "bundle", "public-key": public + "\n"})
        self.assertEqual(r.returncode, 0, r.stderr)
        other = os.path.join(self.dir, "other")
        cli("bundle", "keygen", other)
        r = self.run_step("signature", {"bundle": "bundle", "public-key": Path(other + ".pub").read_text(encoding="utf-8")})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("bundle_signature", r.stderr)
        with open(os.path.join(self.bundle, "roles.json"), "a", encoding="utf-8") as f:
            f.write("\n")
        r = self.run_step("signature", {"bundle": "bundle", "public-key": public})
        self.assertNotEqual(r.returncode, 0)                           # a file changed after signing
        self.assertIn("bundle_signature", r.stderr)


class VsCodeTasksTest(BundleCase):
    DIR = INTEGRATIONS / "vscode"

    def test_every_task_command_runs(self):
        doc = json.loads((self.DIR / "tasks.json").read_text(encoding="utf-8"))
        request = self.DIR / "request.example.json"
        os.makedirs(os.path.join(self.dir, ".vscode"))
        shutil.copy(self.DIR / "smartdelegate.explain.json", os.path.join(self.dir, ".vscode"))
        outputs = {}
        for task in doc["tasks"]:
            self.assertEqual(task["command"], "smartdelegate")
            args = [a.replace("${workspaceFolder}", self.dir).replace("${file}", str(request)) for a in task["args"]]
            self.assertFalse([a for a in args if "${" in a], "an unresolved VS Code variable")
            r = cli(*args, cwd=self.dir)
            self.assertEqual(r.returncode, 0, task["label"] + ": " + r.stderr)
            outputs[task["label"]] = r.stdout
        self.assertEqual(len(outputs), 3)
        explain = json.loads(next(v for k, v in outputs.items() if "explain" in k))
        self.assertEqual((explain["effect"], explain["rule"]), ("allow", "DELEGATE-POLICY-PERMIT"))
        self.assertTrue(explain["explain"])


FLOWISE_HARNESS = r"""
const fs = require("fs");
const body = fs.readFileSync(process.argv[2], "utf8");
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const tool = new AsyncFunction("$customer_id", "$vars", "$flow", body);   // a function body with a top-level return
(async () => {
  const cases = JSON.parse(fs.readFileSync(0, "utf8"));
  const out = [];
  for (const c of cases) out.push(await tool(c.customer_id, c.vars, {}));
  process.stdout.write(JSON.stringify(out));
})().catch(e => { console.error(e); process.exit(1); });
"""


@unittest.skipUnless(NODE, "node is not available: the Flowise tool body is not executed")
class FlowiseToolBodyTest(unittest.TestCase):
    """The Custom Tool body under plain Node (18+, global fetch), against the
    real daemon and the stand-in CRM. Not run inside Flowise."""

    def test_filter_through_the_daemon(self):
        crm = subprocess.Popen([sys.executable, str(EXAMPLES / "fake_crm.py"), "0"], stdout=subprocess.PIPE, text=True)
        try:
            crm_url = re.search(r"http://\S+", crm.stdout.readline()).group(0)
            with Daemon() as daemon, tempfile.TemporaryDirectory() as tmp:
                client = DaemonClient(daemon.url, admin_key=Daemon.ADMIN)
                token = A.delegate_for_task(client, user="alice", agent="support-bot", role="support-agent", task="ticket-7").token
                audit = A.delegate_for_task(client, user="carol", agent="support-bot", role="break-glass", task="incident-1").token
                base = {"SMARTDELEGATE_URL": daemon.url + "/", "SMARTDELEGATE_PEP_KEY": Daemon.PEP, "SMARTDELEGATE_TOKEN": token,
                        "CRM_URL": crm_url, "CRM_API_KEY": "upstream-secret-key"}
                cases = [{"customer_id": "c-1", "vars": base},
                         {"customer_id": "c-1", "vars": {**base, "SMARTDELEGATE_TOKEN": audit}},       # a token that does not cover customers
                         {"customer_id": "c-1", "vars": {**base, "SMARTDELEGATE_TOKEN": ""}},
                         {"customer_id": "c-1", "vars": {**base, "SMARTDELEGATE_PEP_KEY": "wrong-key-wrong-key"}},
                         {"customer_id": "c-404", "vars": base},                                        # the upstream 404 body echoes an ssn
                         {"customer_id": "c-1", "vars": {**base, "SMARTDELEGATE_URL": "http://127.0.0.1:1"}},
                         {"customer_id": "", "vars": base}]
                harness = os.path.join(tmp, "harness.js")
                Path(harness).write_text(FLOWISE_HARNESS, encoding="utf-8")
                env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
                r = subprocess.run([NODE, harness, str(INTEGRATIONS / "flowise" / "SmartDelegateFilter.js")], input=json.dumps(cases),
                                   capture_output=True, text=True, env={**env, "NO_PROXY": "127.0.0.1,localhost"}, timeout=60)
        finally:
            crm.kill()
            crm.wait()
            crm.stdout.close()
        self.assertEqual(r.returncode, 0, r.stderr)
        ok, uncovered, no_token, bad_key, missing, down, no_id = json.loads(r.stdout)
        record = json.loads(ok)
        self.assertEqual(record["name"], "Ada Lovelace")
        self.assertNotIn("ssn", record)
        self.assertNotIn("notes", record)
        self.assertIn("DELEGATE-CAPABILITY-", uncovered)
        self.assertIn("DELEGATE-TOKEN-INVALID", no_token)
        self.assertIn("(unauthorized, DELEGATE-UNAUTHORIZED)", bad_key)
        self.assertIn("DELEGATE-DAEMON-UNREACHABLE", down)
        self.assertIn("DELEGATE-INVALID-ARGUMENTS", no_id)
        self.assertIn("404", missing)
        for text in (uncovered, no_token, bad_key, missing, down, no_id):
            self.assertNotIn("123-45-6789", text)
            self.assertNotIn("Ada", text)


# ---- 10. the playground ------------------------------------------------------

RULES_DRIVER = r"""
const fs = require("fs"), vm = require("vm");
const html = fs.readFileSync(process.argv[2], "utf8");
const a = html.indexOf("// rules:start"), b = html.indexOf("// rules:end");
if (a < 0 || b < a) { console.error("the rules block was not found in the page"); process.exit(2); }
const api = vm.runInNewContext(html.slice(a, b) + "\n({ DATA, issue, narrow, matches, covers });");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const results = input.cases.map(c => {
  const r = api.issue(c.issue);
  return { issue: r, narrows: r.ok ? (c.narrows || []).map(n => api.narrow(r, n)) : [] };
});
const patterns = input.patterns.map(p => [api.matches(p[0], p[1]), api.covers(p[0], p[1])]);
process.stdout.write(JSON.stringify({ data: api.DATA, results: results, patterns: patterns }));
"""


class PlaygroundTest(unittest.TestCase):
    PAGE = SITE / "playground.html"

    @classmethod
    def setUpClass(cls):
        cls.html = cls.PAGE.read_text(encoding="utf-8")

    def page_rules(self, cases: list, patterns: list | None = None) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            driver = os.path.join(tmp, "rules.js")
            Path(driver).write_text(RULES_DRIVER, encoding="utf-8")
            r = subprocess.run([NODE, driver, str(self.PAGE)], input=json.dumps({"cases": cases, "patterns": patterns or []}),
                               capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_page_is_self_contained(self):
        self.assertIn("<title>SmartDelegate playground</title>", self.html)
        self.assertIn("smartdelegate", self.html)
        self.assertIn("pip install sf-smartdelegate", self.html)
        self.assertIn("smartdelegate --demo", self.html)
        self.assertIn("illustrates the delegation rules only", self.html)
        self.assertIn("prefers-color-scheme: dark", self.html)
        self.assertIn('name="viewport"', self.html)
        # nothing is fetched: no URL, no external script, stylesheet, image, font or import
        self.assertEqual(re.findall(r"(?:https?:)?//[A-Za-z0-9.-]+\.[a-z]{2,}", self.html), [])
        for needle in ("<link", "<img", "<iframe", "@import", "url(", " src=", "fetch(", "XMLHttpRequest", "<a "):
            self.assertNotIn(needle, self.html, needle)
        self.assertEqual(len(re.findall(r"<script", self.html)), 1)

    @unittest.skipUnless(NODE, "node is not available: the page's rule functions are not executed")
    def test_embedded_data_is_the_example_bundle(self):
        data = self.page_rules([])["data"]
        self.assertEqual(data["roles"], json.loads((BUNDLE / "roles.json").read_text(encoding="utf-8"))["roles"])
        entities = {f"{e['uid']['type']}::{e['uid']['id']}": [f"{p['type']}::{p['id']}" for p in e["parents"]]
                    for e in json.loads((BUNDLE / "entities.json").read_text(encoding="utf-8"))}
        for uid, parents in data["parents"].items():
            self.assertEqual(parents, entities[uid], uid)
        self.assertEqual(sorted("User::" + u for u in data["users"]), ["User::alice", "User::bob", "User::carol", "User::dave"])
        self.assertEqual(sorted(data["agents"]), sorted(k[7:] for k in entities if k.startswith("Agent::")))
        with Engine({"bundle_dir": str(BUNDLE)}) as e:
            self.assertEqual((data["engine"]["default_ttl"], data["engine"]["max_ttl"]), (e.default_ttl, e.max_ttl))

    @unittest.skipUnless(NODE, "node is not available: the page's rule functions are not executed")
    def test_named_scenarios(self):
        base = {"user": "alice", "agent": "support-bot", "role": "support-agent", "task": "ticket-7", "cap": None, "ttl": None}
        role_cap = json.loads((BUNDLE / "roles.json").read_text(encoding="utf-8"))["roles"]["support-agent"]["cap"]
        wide = {"actor": "summarizer", "cap": {"actions": ["read"], "resources": ["*"], "deny_labels": ["secret"]}, "ttl": None}
        slim = {"actor": "summarizer", "cap": {"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["secret"]}, "ttl": 60}
        cases = [{"issue": base, "narrows": [wide, slim]},
                 {"issue": {**base, "user": "dave"}},
                 {"issue": {**base, "cap": {**role_cap, "budget": {"EUR": 20000}}}},
                 {"issue": {**base, "user": "bob", "role": "supervisor", "task": None}},
                 {"issue": {**base, "user": "bob", "role": "supervisor", "task": "escalation-1"}}]
        granted, dave, budget, no_task, escalation = self.page_rules(cases)["results"]
        self.assertTrue(granted["issue"]["ok"])
        self.assertEqual((granted["issue"]["ttl"], granted["issue"]["cap"]["deny_labels"]), (600, ["secret"]))
        self.assertEqual((granted["narrows"][0]["code"], granted["narrows"][0]["rule"]), ("widening", "DELEGATE-WIDENING"))
        self.assertEqual((granted["narrows"][1]["ok"], granted["narrows"][1]["ttl"], granted["narrows"][1]["chain"]),
                         (True, 60, ["support-bot", "summarizer"]))
        self.assertEqual(dave["issue"]["rule"], "DELEGATE-ROLE-NOT-HELD")
        self.assertEqual(budget["issue"]["rule"], "DELEGATE-ROLE-EXCEEDED")
        self.assertIn("budget 20000 EUR exceeds the role's 10000", budget["issue"]["message"])
        self.assertEqual(no_task["issue"]["rule"], "DELEGATE-ROLE-EXCEEDED")
        self.assertEqual((escalation["issue"]["ok"], escalation["issue"]["ttl"]), (True, 300))

    @unittest.skipUnless(NODE, "node is not available: the page's rule functions are not executed")
    def test_pattern_functions_agree_with_tokens_py(self):
        from sf_smartdelegate.tokens import _covers, _matches
        rnd = random.Random(11)
        pool = ["", "*", "read", "re*", "rea*", "read*", "crm.customer/*", "crm.customer/c-1", "crm.customer/c-*", "crm.*", "crm.customer/",
                "billing.refund/*", "a", "ab", "a*", "ab*", "**", "a**"]
        pairs = [[rnd.choice(pool), rnd.choice(pool)] for _ in range(600)]
        got = self.page_rules([], pairs)["patterns"]
        for (parent, child), (m, c) in zip(pairs, got):
            self.assertEqual(m, _matches(parent, child), ("matches", parent, child))
            self.assertEqual(c, _covers(parent, child), ("covers", parent, child))

    @unittest.skipUnless(NODE, "node is not available: the page's rule functions are not executed")
    def test_verdicts_agree_with_the_engine_on_random_requests(self):
        """Every verdict the page can show (code, rule id, message, or the
        granted capability and lifetime) against the Python engine on the
        conformance bundle: 400 issuance requests, and three sub-agent
        requests for each one that is granted."""
        rnd = random.Random(20240607)
        actions = ["read", "create", "update", "delete", "*", "re*", "r*d", "", "cr*"]
        resources = ["crm.customer/*", "crm.customer/c-1", "billing.refund/*", "hr.salary/*", "*", "crm.*", "crm.customer/c-*",
                     "billing.*", "a*b/*", "crm.customer/**", "hr.salary/e-1"]
        labels = ["secret", "financial", "pii", "internal"]
        ttls = [None, None, None, 1, 60, 120, 300, 600, 601, 900, 3600, 5000, 0, -5]
        tasks = [None, "ticket-7", "escalation-1", "incident-9", "escalation", "other", "escalation-"]
        budgets = [{}, {"EUR": 0}, {"EUR": 5000}, {"EUR": 10000}, {"EUR": 10001}, {"EUR": 20000}, {"EUR": 50000}, {"EUR": 60000},
                   {"EUR": -1}, {"USD": 100}, {"EUR": 100, "USD": 1}]
        roles = json.loads((BUNDLE / "roles.json").read_text(encoding="utf-8"))["roles"]

        def cap(base):
            if rnd.random() < 0.3:
                return None
            if base and rnd.random() < 0.6:        # a variation of the ceiling: most of the interesting cases are near it
                c = json.loads(json.dumps(base))
                kind = rnd.choice(["actions", "resources", "deny_labels", "budget", "same", "shrink"])
                if kind == "actions":
                    c["actions"] = rnd.sample(actions, rnd.randint(0, 2))
                elif kind == "resources":
                    c["resources"] = rnd.sample(resources, rnd.randint(0, 2))
                elif kind == "deny_labels":
                    c["deny_labels"] = rnd.sample(labels, rnd.randint(0, 3))
                elif kind == "budget":
                    c["budget"] = rnd.choice(budgets)
                elif kind == "shrink":
                    c["actions"] = c["actions"][:rnd.randint(0, len(c["actions"]))]
                    c["resources"] = c["resources"][:rnd.randint(0, len(c["resources"]))]
                return c
            c = {"actions": rnd.sample(actions, rnd.randint(0, 3)), "resources": rnd.sample(resources, rnd.randint(0, 3))}
            if rnd.random() < 0.5:
                c["deny_labels"] = rnd.sample(labels, rnd.randint(0, 3))
            if rnd.random() < 0.2:
                c["deny_fields"] = rnd.sample(["ssn", "email"], rnd.randint(0, 2))
            if rnd.random() < 0.5:
                c["budget"] = rnd.choice(budgets)
            return c

        def norm(r):
            if r.get("ok"):
                return {"ok": True, "user": r["user"], "chain": r["chain"], "role": r["role"], "cap": r["cap"], "ttl": r["expires_in"]}
            return {"ok": False, "code": r["error"]["code"], "rule": r["error"]["rule"], "message": r["error"]["message"]}

        cases, expected, seen = [], [], {}
        with Engine({"bundle_dir": str(BUNDLE), "allow_test_clock": True}) as engine:
            for _ in range(400):
                role = rnd.choice(list(roles) + (["no-such-role"] if rnd.random() < 0.03 else []))
                issue = {"user": rnd.choice(["alice", "bob", "carol", "dave"]),
                         "agent": rnd.choice(["support-bot"] * 5 + ["refund-helper", "summarizer", "rogue-bot", "ghost"]),
                         "role": role, "task": rnd.choice(tasks), "cap": cap(roles.get(role, {}).get("cap")), "ttl": rnd.choice(ttls)}
                r = engine.call("issue_token", {**{k: v for k, v in issue.items() if v is not None}, "now": T})
                case, want = {"issue": issue, "narrows": []}, {"issue": norm(r), "narrows": []}
                if r.get("ok"):
                    for _ in range(3):
                        n = {"actor": rnd.choice(["refund-helper", "summarizer", "summarizer", "rogue-bot", "support-bot", "ghost"]),
                             "cap": cap(r["cap"]), "ttl": rnd.choice(ttls)}
                        case["narrows"].append(n)
                        want["narrows"].append(norm(engine.call("exchange_token", {"subject_token": r["token"], "now": T,
                                                                                    **{k: v for k, v in n.items() if v is not None}})))
                cases.append(case)
                expected.append(want)

        got = self.page_rules(cases)["results"]
        keys_ok, keys_refused = ("ok", "user", "chain", "role", "cap", "ttl"), ("ok", "code", "rule", "message")

        def compare(kind, request, want, have_):
            seen[kind + ":" + (want.get("code") or "granted")] = seen.get(kind + ":" + (want.get("code") or "granted"), 0) + 1
            keys = keys_ok if want["ok"] else keys_refused
            self.assertEqual({k: have_.get(k) for k in keys}, {k: want[k] for k in keys}, f"{kind} {json.dumps(request)}")

        for case, want, have_ in zip(cases, expected, got):
            compare("issue", case["issue"], want["issue"], have_["issue"])
            self.assertEqual(len(have_["narrows"]), len(want["narrows"]))
            for n, wn, hn in zip(case["narrows"], want["narrows"], have_["narrows"]):
                compare("narrow", n, wn, hn)
        # the sample must reach every verdict the page can show, or the comparison proves little
        for verdict in ("issue:granted", "issue:role_not_held", "issue:role_exceeded", "issue:invalid_cap", "issue:delegation_denied",
                        "narrow:granted", "narrow:widening", "narrow:delegation_denied"):
            self.assertGreaterEqual(seen.get(verdict, 0), 5, f"{verdict}: {seen}")


if __name__ == "__main__":
    unittest.main()
