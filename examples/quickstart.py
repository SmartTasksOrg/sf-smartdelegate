"""SmartDelegate in an agent, in-process. From the repository root:

    pip install cryptography
    python examples/quickstart.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))   # the reference package, when it is not installed

# --- the integration: 9 lines -------------------------------------------------
from sf_smartdelegate import Denied, Engine, Guard

iam = Engine({"bundle_dir": str(ROOT / "spec" / "conformance" / "bundle")})
task = iam.issue_token("support-bot", {"actions": ["read"], "resources": ["crm.customer/*"]}, user="alice")
guard = Guard(iam, token=lambda: task["token"])


@guard.tool(action="read", resource="crm.customer", id="customer_id")
def get_customer(customer_id):
    return CRM[customer_id]  # your real tool body
# ------------------------------------------------------------------------------


CRM = {"c-1": {"id": "c-1", "name": "Ada Lovelace", "email": "ada@example.com", "ssn": "123-45-6789", "region": "EU", "notes": "threatened to churn"}}

print("what the tool returns to the model:", get_customer("c-1"))

helper = iam.exchange_token(task["token"], "refund-helper", cap={"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["pii"]}, ttl=300)
task = helper
print("the same tool for a sub-agent     :", get_customer("c-1"), "chain:", helper["chain"])

try:
    iam.exchange_token(helper["token"], "summarizer", cap={"actions": ["read", "update"], "resources": ["crm.customer/*"]}, ttl=60)
except Exception as e:
    print("a sub-agent cannot widen its token:", e)

iam.revoke(helper["token_id"])
try:
    get_customer("c-1")
except Denied as e:
    print("after revocation                  :", e.reason)
