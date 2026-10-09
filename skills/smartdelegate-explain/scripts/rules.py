#!/usr/bin/env python3
"""What a SmartDelegate rule id means and who can change the outcome.

    python3 skills/smartdelegate-explain/scripts/rules.py DELEGATE-CAPABILITY-RESOURCE
    python3 skills/smartdelegate-explain/scripts/rules.py --all
    smartdelegate audit tail -n 200 | python3 skills/smartdelegate-explain/scripts/rules.py --decision d-90ae617b8eeaa8c2

With --decision the audit records are read from standard input (JSON Lines, as
`smartdelegate audit tail` prints them) and the record with that decision id is
explained: who, what, the reason, the deciding policies. Reads only; standard
library only. Exit status: 0 found, 1 not found or unknown rule, 2 usage.
"""
from __future__ import annotations

import json
import sys

#: rule id -> (what happened, who can change the outcome and how)
RULES = {
    # decisions (spec: docs/SCOPE.md section 7, in decision order)
    "DELEGATE-TOKEN-INVALID": ("No token was presented, or it is forged, altered, from another issuer, or dated in the future.",
                               "Nobody should work around this. Obtain a token through delegation; if a real token fails, the enforcement point may use another engine's key."),
    "DELEGATE-TOKEN-EXPIRED": ("The token's lifetime is over.",
                               "The human starts the task again: a new delegation. The lifetime is the role's max_ttl."),
    "DELEGATE-TOKEN-REVOKED": ("The token, a token it was derived from, or every token of its user was revoked.",
                               "Deliberate. The human asks for a new delegation; it succeeds only if they still hold the role."),
    "DELEGATE-UNKNOWN-RESOURCE": ("The resource path is not in the bundle's catalog.",
                                  "The policy author adds it to catalog.json, or the enforcement point's mapping names the wrong path."),
    "DELEGATE-UNKNOWN-FIELD": ("A field named in the request is not in the catalog.",
                               "The policy author adds the field to catalog.json; unlisted fields are dropped by default."),
    "DELEGATE-TENANT-MISMATCH": ("The token's tenant differs from the tenant of the resource.",
                                 "Nobody: cross-tenant access is refused. Check the enforcement point sends the record's real tenant."),
    "DELEGATE-CAPABILITY-ACTION": ("The token does not carry this action.",
                                   "The human delegates a role whose ceiling includes the action. A sub-agent asks its parent for less narrowing, never more than the parent holds."),
    "DELEGATE-CAPABILITY-RESOURCE": ("The token does not cover this resource or this id.",
                                     "As above: a different role, or a parent that hands on this resource."),
    "DELEGATE-NO-MATCHING-PERMIT": ("No policy permits this agent, for this human, in this role, to do this. Default deny.",
                                    "The policy author, if the request is legitimate: a new permit, reviewed and tested."),
    "DELEGATE-POLICY-FORBID": ("A forbid policy applies. The decision names it in `policies`.",
                               "The policy owner. A forbid is deliberate; do not look for another path to the same data."),
    "DELEGATE-POLICY-ERROR": ("A forbid policy could not be evaluated (usually a resource attribute it reads was not sent), so the request is denied.",
                              "The enforcement point's owner sends the attribute, or the policy author guards it with `has`."),
    "DELEGATE-OBLIGATION-UNRESOLVED": ("A row filter needs a value the request or the user's attributes did not supply.",
                                       "The directory sync's attribute map (user attributes), or the enforcement point (request context)."),
    "DELEGATE-RATE-LIMITED": ("The deciding policy's rate limit is used up for this agent and user.",
                              "Wait for the window. Do not retry in a loop."),
    "DELEGATE-BUDGET-EXCEEDED": ("The spend would exceed the budget of this token or of a token above it in the chain.",
                                 "The human, with a new task. Splitting the spend across sub-agents does not help: it is charged to the whole chain."),
    "DELEGATE-APPROVAL-REQUIRED": ("Policy holds this exact call for a second human. The decision carries the approval id.",
                                   "A human whom policy lets approve, who is not the user the agent acts for. Then retry the same call once."),
    "DELEGATE-FIELD-DENIED": ("Strict mode: the data the tool was about to write contains a field this principal may not use. The detail names the fields.",
                              "Remove those fields from the input. They are not dropped for you."),
    "DELEGATE-POLICY-PERMIT": ("Allowed. Obligations (field mask, row filter) still apply to the data.", "Nothing to change."),
    "DELEGATE-SHADOW-ALLOW": ("Shadow mode: the request would have been denied and was let through and logged.",
                              "The operator: shadow mode enforces nothing. See `would_deny` in the decision."),
    # issuance and exchange (spec/API.md, spec/ROLES.md)
    "DELEGATE-ROLE-NOT-HELD": ("The human does not hold the role right now (stored membership, or the groups the identity provider sent).",
                               "The human's access administrator, at the identity provider. Not the agent, and not by naming other groups."),
    "DELEGATE-ROLE-EXCEEDED": ("More was asked than the role allows: capability, budget, a task or an agent the role does not list.",
                               "Ask for less: omit the capability to get the role's ceiling; use a task name and agent the role lists."),
    "DELEGATE-UNKNOWN-ROLE": ("roles.json has no role of that name.", "Use a name from `smartdelegate info`."),
    "DELEGATE-ROLE-REQUIRED": ("This engine issues root tokens only for a named role.", "Name the role the human lends."),
    "DELEGATE-DELEGATION-DENIED": ("No policy lets this human (or this agent) hand authority to that agent.",
                                   "The policy author: action `delegate` on the receiving agent."),
    "DELEGATE-UNKNOWN-AGENT": ("The receiving agent is not in entities.json.", "The bundle's owner registers the agent."),
    "DELEGATE-WIDENING": ("A sub-agent token was asked to carry more than its parent, to drop one of the parent's deny lists, or to change the role.",
                          "Ask for the same or less. Repeat the parent's deny_labels and deny_fields in the capability."),
    "DELEGATE-DEPTH-EXCEEDED": ("The delegation chain would be longer than the engine's max_depth.", "Restructure the task; do not chain further."),
    "DELEGATE-INVALID-CAP": ("The capability is malformed, or a root token was asked without a capability and without a role.", "Fix the request."),
    "DELEGATE-ID-TOKEN-INVALID": ("The identity provider's ID token did not verify (signature, issuer, audience, expiry, group claim), or predates the user's revocation.",
                                  "The human signs in again."),
    "DELEGATE-NO-IDP": ("An ID token was presented and the engine has no identity provider configured.", "The operator configures `idp`."),
    # approvals
    "DELEGATE-SELF-APPROVAL": ("The approver is the user the agent acts for.", "A different human approves."),
    "DELEGATE-APPROVAL-DENIED": ("No policy lets this person approve this request.", "Someone whom policy permits (action `approve`)."),
    "DELEGATE-UNKNOWN-APPROVAL": ("No pending request has that id: it was approved, it expired, or the call differs from the one that was held.",
                                  "Repeat the exact call to obtain the current approval id."),
    # integration layer and MCP server
    "DELEGATE-INVALID-ARGUMENTS": ("The enforcement point could not turn the call's arguments into a request.", "Fix the arguments (id, whole minor units, a record object)."),
    "DELEGATE-UNKNOWN-TOOL": ("The tool has no binding. Unbound tools are denied.", "The integrator binds the tool to an action and a resource."),
    "DELEGATE-TOOL-FAILED": ("The tool raised; its message is withheld because it can echo record data.", "The tool's owner."),
    "DELEGATE-DAEMON-UNREACHABLE": ("The enforcement point could not reach the decision daemon. No decision, no call.", "The operator restores the daemon."),
    "DELEGATE-ADMIN-REQUIRED": ("The MCP server was started without --admin.", "The operator, deliberately."),
    "DELEGATE-TOOL-NOT-ALLOWED": ("The MCP server's --allow-tools list does not include this privileged tool.", "The operator, deliberately."),
    "DELEGATE-OPS-REQUIRED": ("The MCP server was started without --ops.", "The operator."),
}


def explain(rule: str) -> str:
    what, who = RULES[rule]
    return f"{rule}\n  what: {what}\n  who can change it: {who}"


def main(argv: list) -> int:
    if not argv or argv[0] in ("--help", "-h"):
        print(__doc__)
        return 0 if argv else 2
    if argv == ["--all"]:
        print("\n".join(explain(r) for r in RULES))
        return 0
    if len(argv) == 2 and argv[0] == "--decision":
        for line in sys.stdin.read().split("\n"):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict) and r.get("decision_id") == argv[1] and r.get("event") == "decision":
                rule = "DELEGATE-" + str(r.get("reason")).upper().replace("_", "-")
                chain = " -> ".join(r.get("chain") or []) or "?"
                print(f"decision {argv[1]} (audit record {r.get('seq')}): {r.get('effect')}\n  who: user {r.get('user')} via {chain}, role {r.get('role')}, task {r.get('task')}\n"
                      f"  asked: {r.get('action')} {r.get('resource')}\n  detail: {r.get('detail') or '-'}\n  policies: {', '.join(r.get('policies') or []) or '-'}")
                print(explain(rule) if rule in RULES else f"{rule}\n  not in this table: see spec/API.md")
                return 0
        print(f"no decision record with id {argv[1]} in the input (was it a dry run or an explain? those are not logged)", file=sys.stderr)
        return 1
    if len(argv) == 1 and argv[0] in RULES:
        print(explain(argv[0]))
        return 0
    print(f"unknown rule or usage: {' '.join(argv)}", file=sys.stderr)
    return 1 if len(argv) == 1 else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
