"""AWS: down-scope a role session to a SmartDelegate capability, and read a
human's ceiling from the IAM policy simulator.

Nothing here imports boto3. `assume_role_request` returns the keyword
arguments for `sts_client.assume_role(**kwargs)`; `simulation_request` those
for `iam_client.simulate_principal_policy(**kwargs)`.

Written from:
  https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
      Policy: inline session policy, at most 2,048 characters; DurationSeconds 900..43200
      (default 3600); RoleSessionName 2..64 characters of [\\w+=,.@-]; Tags: at most 50, key
      <= 128, value <= 256; TransitiveTagKeys
  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html
      the role's trust policy must allow sts:TagSession; session tags appear in CloudTrail
      under requestParameters.principalTags; policy and tags share a packed size limit
  https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html
      PolicySourceArn, ActionNames, ResourceArns -> EvaluationResults[] {EvalActionName,
      EvalResourceName, EvalDecision}, IsTruncated, Marker
Tested only with a fake STS client and hand-written simulator results. AWS was not contacted.

What a session policy does: the session's permissions are the intersection of the role's
identity policies and the session policy. It can only take away. So the credential is never
wider than BOTH the role (`role.bindings.aws.role_arn`) and the capability as mapped.

# UNVERIFIED: EvalDecision values. The page read shows "allowed" and "implicitDeny";
# "explicitDeny" is from memory. Only the exact string "allowed" counts as allowed here.
# UNVERIFIED: how the simulator treats `*` inside a ResourceArns entry. `simulation_request`
# sends each mapped resource template with {id} replaced by `*`; a rule counts as allowed only
# if that exact entry comes back "allowed".
# UNVERIFIED: the packed (binary) size limit of policy plus tags cannot be computed locally; STS
# can still refuse a request that is under 2,048 characters. `assume_role` then raises.
# UNVERIFIED: that `?` and `${...}` are the only characters besides `*` with a special meaning in
# an IAM Resource element. Ids containing them are not granted (reported as "unsafe_id").
"""
from __future__ import annotations

import json
import re
import time

from .. import tokens
from . import BridgeError
from .cloudmap import allowed_pairs, as_cap, not_enforced, pairs_to_cap, rules, select

POLICY_MAX_CHARS = 2048
DURATION_MIN, DURATION_MAX = 900, 43200
TAG_KEYS = {"user": "sd_user", "agent": "sd_agent", "role": "sd_role", "task": "sd_task", "token_id": "sd_token_id"}
_ROLE_ARN = re.compile(r"arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+")
_DENY_ALL = {"Effect": "Deny", "Action": "*", "Resource": "*"}


def _safe_id(i: str) -> bool:
    return "?" not in i and "${" not in i and "*" not in i[:-1]


def _statements(cap, cloud_map: dict) -> tuple:
    grants, skipped = select(cap, rules(cloud_map, "aws"))
    merged: dict = {}
    for g in grants:
        allow = g.rule["allow"]
        resources = []
        for t in allow["Resource"]:
            if "{id}" in t:
                if not _safe_id(g.id):
                    skipped.append({"action": g.rule["action"], "resource": g.resource, "reason": "unsafe_id"})
                    resources = []
                    break
                resources.append(t.replace("{id}", g.id))
            elif g.whole:
                resources.append(t)
            else:
                skipped.append({"action": g.rule["action"], "resource": g.resource, "reason": "cannot_narrow", "template": t})
        if not resources:
            continue
        key = (tuple(sorted(set(allow["Action"]))), json.dumps(allow.get("Condition"), sort_keys=True))
        merged.setdefault(key, set()).update(resources)
    out = []
    for (actions, cond), res in sorted(merged.items()):
        st = {"Effect": "Allow", "Action": list(actions), "Resource": sorted(res)}
        if cond != "null":
            st["Condition"] = json.loads(cond)
        out.append(st)
    return out, skipped


def session_policy(cap, cloud_map: dict) -> dict:
    """The IAM session policy for a capability.

    Guarantees: it has Allow statements only for (action, resource) pairs of
    the capability that the map's `aws` rules cover, with every resource
    narrowed to the capability; anything unmapped is absent (default deny);
    the same inputs give the same policy. When nothing maps, the policy is a
    single explicit Deny of everything - an empty policy would not be valid
    and NO policy would leave the session with the role's full permissions.
    Raises BridgeError("policy_too_large") when the compact JSON exceeds
    2,048 characters, the documented limit for a session policy.

    Not enforced by this policy: deny_labels, deny_fields and budget of the
    capability (see `session_policy_report`)."""
    statements, _ = _statements(cap, cloud_map)
    policy = {"Version": "2012-10-17", "Statement": statements or [dict(_DENY_ALL)]}
    size = len(policy_json(policy))
    if size > POLICY_MAX_CHARS:
        raise BridgeError("policy_too_large", f"the session policy is {size} characters; AWS allows {POLICY_MAX_CHARS}. "
                                              "Narrow the capability or shorten the map", {"size": size})
    return policy


def policy_json(policy: dict) -> str:
    """The compact JSON text that is sent as `Policy` (and counted against the limit)."""
    return json.dumps(policy, separators=(",", ":"), sort_keys=True)


def session_policy_report(cap, cloud_map: dict) -> dict:
    """{"policy", "size", "skipped", "not_enforced"}: the policy plus what the
    capability has that the policy does not express, so that nothing is
    dropped silently."""
    policy = session_policy(cap, cloud_map)
    return {"policy": policy, "size": len(policy_json(policy)), "skipped": _statements(cap, cloud_map)[1],
            "not_enforced": not_enforced(cap)}


def _principal(v) -> dict:
    """user / agent / role / task / token_id / exp / cap from a models.Grant, an
    issue_token result, an inspect_token result, or a token's claims."""
    if hasattr(v, "token_id") and hasattr(v, "chain"):  # models.Grant
        p = {"user": v.user, "chain": list(v.chain), "role": v.role, "task": getattr(v, "task", None), "token_id": v.token_id, "exp": v.expires_at,
             "cap": v.capability.to_json()}
    elif isinstance(v, dict) and isinstance(v.get("claims"), dict):
        return _principal(v["claims"])
    elif isinstance(v, dict) and "act" in v and "sub" in v:
        p = {"user": tokens.user_of(v), "chain": tokens.chain_of(v), "role": v.get("role"), "task": v.get("task"),
             "token_id": v.get("jti"), "exp": v.get("exp"), "cap": v.get("cap")}
    elif isinstance(v, dict) and "token_id" in v:
        p = {"user": v.get("user"), "chain": list(v.get("chain") or []), "role": v.get("role"), "task": v.get("task"),
             "token_id": v.get("token_id"), "exp": v.get("expires_at"), "cap": v.get("cap")}
    else:
        raise BridgeError("invalid_input", "expected a Grant, an issue_token result, or token claims")
    if not (isinstance(p["user"], str) and p["user"] and p["chain"] and isinstance(p["token_id"], str) and p["token_id"]
            and isinstance(p["exp"], int) and not isinstance(p["exp"], bool)):
        raise BridgeError("invalid_input", "the grant or claims lack user, agent chain, token id or expiry")
    return p


def _clean(s: str, extra: str, limit: int) -> str:
    return re.sub(rf"[^A-Za-z0-9_{re.escape(extra)}]", "-", s)[:limit]


def duration_for(expires_at: int, now: int, max_duration: int = 3600) -> tuple:
    """(DurationSeconds, seconds by which the credential outlives the token).
    DurationSeconds = min(seconds the token has left, max_duration), raised to
    AWS's minimum of 900. When the token has less than 900 seconds left the
    credential therefore outlives it by the second number; the caller decides
    whether that is acceptable. An expired token raises."""
    left = expires_at - now
    if left <= 0:
        raise BridgeError("token_expired", "the capability token has expired; no cloud credential for it")
    seconds = max(DURATION_MIN, min(left, max_duration, DURATION_MAX))
    return seconds, max(0, seconds - left)


def assume_role_request(grant_or_claims, cap, cloud_map: dict, role_arn: str, *, max_duration: int = 3600, now: int | None = None) -> dict:
    """Keyword arguments for `sts.assume_role`, bounded by a capability token.

    grant_or_claims  a `models.Grant`, an issue_token / inspect_token result, or verified token claims
    cap              the capability to down-scope to; None uses the token's own
    role_arn         normally `role.bindings["aws"]["role_arn"]` from roles.json

    Guarantees: `Policy` is `session_policy(cap, cloud_map)` (so the session
    is no wider than the capability as mapped, and no wider than the role);
    `RoleSessionName` is built from the agent and the token id and contains
    only [A-Za-z0-9_+=,.@-], 2..64 characters; `DurationSeconds` is
    `duration_for(...)`; `Tags` carry user, agent, role, task and token id
    (keys sd_user, sd_agent, sd_role, sd_task, sd_token_id; absent values are
    left out) and all are transitive, so CloudTrail shows who the session
    acted for. The role's trust policy must allow sts:TagSession. No secret
    is in the result."""
    if not isinstance(role_arn, str) or not _ROLE_ARN.fullmatch(role_arn):
        raise BridgeError("invalid_input", "role_arn is not an IAM role ARN")
    p = _principal(grant_or_claims)
    use = cap if cap is not None else p["cap"]
    if use is None:
        raise BridgeError("invalid_input", "no capability: pass cap or a grant that carries one")
    if cap is not None and p["cap"] is not None:
        try:  # an explicit cap must not exceed the token it is said to belong to
            as_cap(cap).check_narrower_than(as_cap(p["cap"]))
        except Exception as e:
            raise BridgeError("widening", f"the capability asked for is wider than the token's: {getattr(e, 'message', e)}") from None
    policy = session_policy(use, cloud_map)
    seconds, _ = duration_for(p["exp"], int(time.time()) if now is None else now, max_duration)
    agent = p["chain"][-1]
    name = _clean(f"{agent}-{p['token_id']}", "+=,.@-", 64)
    values = {"user": p["user"], "agent": agent, "role": p["role"], "task": p["task"], "token_id": p["token_id"]}
    tags = [{"Key": TAG_KEYS[k], "Value": _clean(str(v), " .:/=+@-", 256)} for k, v in values.items() if v]
    return {"RoleArn": role_arn, "RoleSessionName": name if len(name) >= 2 else name + "-x", "Policy": policy_json(policy),
            "DurationSeconds": seconds, "Tags": tags, "TransitiveTagKeys": [t["Key"] for t in tags]}


def assume_role(request: dict, sts_client) -> dict:
    """Call `sts_client.assume_role(**request)` on an injected boto3-like
    client and return the `Credentials` of the answer (AccessKeyId,
    SecretAccessKey, SessionToken, Expiration). Any failure raises
    BridgeError("aws_error") naming the exception type only; the caller never
    gets a wider credential as a fallback."""
    if "Policy" not in request:
        raise BridgeError("invalid_input", "refusing to assume a role without a session policy")
    try:
        answer = sts_client.assume_role(**request)
    except Exception as e:
        raise BridgeError("aws_error", f"sts.assume_role failed: {type(e).__name__}") from None
    creds = answer.get("Credentials") if isinstance(answer, dict) else None
    if not isinstance(creds, dict) or not all(creds.get(k) for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")):
        raise BridgeError("malformed_response", "sts.assume_role returned no credentials")
    return creds


# ---- ceiling -------------------------------------------------------------------

def _concrete(rule: dict) -> tuple | None:
    """(actions, resources) to simulate for a rule, or None when the rule
    names an action with a wildcard (which cannot be shown fully allowed)."""
    actions = rule["allow"]["Action"]
    if any("*" in a or "?" in a for a in actions):
        return None
    return sorted(set(actions)), sorted({r.replace("{id}", "*") for r in rule["allow"]["Resource"]})


def simulation_request(cloud_map: dict, principal_arn: str) -> dict:
    """Keyword arguments for `iam.simulate_principal_policy` that ask, for
    the human's IAM principal, about every action and resource the map's
    `aws` rules name ({id} replaced by `*`). Rules with a wildcard action are
    left out and can never enter the ceiling. Page through the results
    (IsTruncated / Marker) and give all of them to `ceiling_from_simulation`."""
    if not isinstance(principal_arn, str) or not principal_arn.startswith("arn:"):
        raise BridgeError("invalid_input", "principal_arn must be the ARN of the human's IAM user or role")
    actions, resources = set(), set()
    for r in rules(cloud_map, "aws"):
        c = _concrete(r)
        if c:
            actions.update(c[0])
            resources.update(c[1])
    if not actions:
        raise BridgeError("nothing_to_simulate", "the map has no aws rule with concrete actions")
    return {"PolicySourceArn": principal_arn, "ActionNames": sorted(actions), "ResourceArns": sorted(resources)}


def _results(results) -> list:
    if isinstance(results, dict):
        results = [results]
    if not isinstance(results, list):
        raise BridgeError("invalid_input", "simulation results must be a response, a list of responses, or a list of EvaluationResults")
    out = []
    for n, r in enumerate(results):
        if isinstance(r, dict) and "EvaluationResults" in r:
            if r.get("IsTruncated") and n == len(results) - 1:
                raise BridgeError("truncated_pagination", "the simulator results are truncated (IsTruncated); fetch every page first")
            if not isinstance(r["EvaluationResults"], list):
                raise BridgeError("malformed_response", "EvaluationResults is not a list")
            out.extend(r["EvaluationResults"])
        else:
            out.append(r)
    for r in out:
        if not isinstance(r, dict) or not all(isinstance(r.get(k), str) for k in ("EvalActionName", "EvalResourceName", "EvalDecision")):
            raise BridgeError("malformed_response", "an evaluation result lacks EvalActionName, EvalResourceName or EvalDecision")
    return out


def ceiling_detail(results, cloud_map: dict) -> dict:
    """`cloudmap.pairs_to_cap` of the pairs the simulator shows fully allowed:
    {"cap", "pairs", "dropped"}."""
    decided: dict = {}
    for r in _results(results):
        key = (r["EvalActionName"], r["EvalResourceName"])
        decided[key] = decided.get(key, True) and r["EvalDecision"] == "allowed"
    rule_list = rules(cloud_map, "aws")
    ok = []
    for rule in rule_list:
        c = _concrete(rule)
        ok.append(bool(c) and all(decided.get((a, res)) is True for a in c[0] for res in c[1]))
    return pairs_to_cap(allowed_pairs(rule_list, ok))


def ceiling_from_simulation(results, cloud_map: dict) -> dict:
    """What the simulated principal may do, as a capability {"actions",
    "resources"} to cap a role with (`ceiling.cap_role`).

    Guarantee: a SmartDelegate (action, resource) pair is in the result only
    if every action and resource the map gives for it - in every rule that
    overlaps the pair - came back with EvalDecision "allowed". A missing
    result, any other decision, or a truncated result set keeps the pair out.
    Since a capability is a product, pairs that do not fit are dropped, never
    rounded up; `ceiling_detail` lists them."""
    return ceiling_detail(results, cloud_map)["cap"]
