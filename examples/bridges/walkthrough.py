"""SmartDelegate bridges, end to end, with fakes. No network, no cloud account.

    pip install cryptography
    python examples/bridges/walkthrough.py

What it shows:
  1. directory sync (a FAKE Microsoft Graph) -> entities.json
  2. Entra ID-token claims -> groups -> core.delegate(role=..., groups=...) -> token
  3. token -> aws.assume_role_request for the role's bindings.aws.role_arn; the session policy
     is no wider than the token (checked here with a small IAM matcher)
  4. the human leaves the group in the directory; the sync runs; the token issued before the
     removal is revoked (revoke-by-user) and a new delegation is refused

Nothing here contacts Microsoft or AWS: the directory is the `FakeGraph` class below, the STS
client is `FakeSts`, and the ID-token claims are a dict (in production: the claims of an ID
token you have verified, or pass the token itself as `id_token=` and let the engine verify it).
"""
import json
import re
import shutil
import sys
import tempfile
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "src"))

from sf_smartdelegate import core  # noqa: E402
from sf_smartdelegate.bridges import aws, claims, directory, entra  # noqa: E402
from sf_smartdelegate.errors import EngineError, rule_id  # noqa: E402

SUPPORT, SUPERVISORS = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
ALICE = "aaaaaaaa-0000-0000-0000-000000000001"


class FakeGraph:
    """Just enough of Microsoft Graph v1.0 for `entra.fetch`: /users, /groups,
    /groups/{id}/transitiveMembers, two items per page with @odata.nextLink."""

    def __init__(self):
        self.users = {ALICE: "alice@example.com", "aaaaaaaa-0000-0000-0000-000000000002": "bob@example.com",
                      "aaaaaaaa-0000-0000-0000-000000000003": "erin@example.com", "aaaaaaaa-0000-0000-0000-000000000004": "frank@example.com",
                      "aaaaaaaa-0000-0000-0000-000000000005": "grace@example.com"}
        self.groups = {SUPPORT: ("Support", set(self.users)), SUPERVISORS: ("Supervisors", {"aaaaaaaa-0000-0000-0000-000000000002"})}

    def __call__(self, method, url, headers, body):
        u = urllib.parse.urlsplit(url)
        q = dict(urllib.parse.parse_qsl(u.query))
        assert u.hostname == "graph.microsoft.com" and headers["Authorization"] == "Bearer fake-graph-token"
        path = u.path[len("/v1.0"):]
        if path == "/users":
            items = [{"id": i, "userPrincipalName": n, "accountEnabled": True} for i, n in sorted(self.users.items())]
        elif path == "/groups":
            items = [{"id": g, "displayName": v[0]} for g, v in sorted(self.groups.items())]
        else:
            items = [{"@odata.type": "#microsoft.graph.user", "id": m} for m in sorted(self.groups[path.split("/")[2]][1])]
        skip = int(q.get("$skiptoken", 0))
        out = {"value": items[skip:skip + 2]}
        if skip + 2 < len(items):
            out["@odata.nextLink"] = f"https://graph.microsoft.com{u.path}?$select={q['$select']}&$skiptoken={skip + 2}"
        return 200, {"content-type": "application/json"}, json.dumps(out).encode()


class FakeSts:
    def assume_role(self, **kwargs):
        self.request = kwargs
        return {"Credentials": {"AccessKeyId": "ASIAFAKE", "SecretAccessKey": "fake", "SessionToken": "fake", "Expiration": "soon"}}


def iam_allows(policy: dict, action: str, arn: str) -> bool:
    """A minimal IAM evaluation of a session policy: `*` and `?` wildcards, Deny wins."""
    rx = lambda p: re.compile("".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in p) + r"\Z", re.S)
    lst = lambda v: v if isinstance(v, list) else [v]
    hit = lambda st: any(rx(a.lower()).match(action.lower()) for a in lst(st["Action"])) and any(rx(r).match(arn) for r in lst(st["Resource"]))
    return not any(st["Effect"] == "Deny" and hit(st) for st in policy["Statement"]) and any(st["Effect"] == "Allow" and hit(st) for st in policy["Statement"])


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="smartdelegate-bridges-demo-"))
    try:
        bundle = work / "bundle"
        shutil.copytree(core.EXAMPLE_BUNDLE, bundle)
        # one more role for the demo: support staff may lend an agent read access to the report exports
        roles = json.loads((bundle / "roles.json").read_text(encoding="utf-8"))
        roles["roles"]["report-reader"] = {
            "members": [{"type": "Group", "id": "support"}],
            "cap": {"actions": ["read"], "resources": ["s3.object/reports/*"]},
            "max_ttl": 900,
            "bindings": {"aws": {"role_arn": "arn:aws:iam::123456789012:role/crm-exports-reader"}}}
        (bundle / "roles.json").write_text(json.dumps(roles, indent=2), encoding="utf-8")
        cloud_map = json.loads((HERE / "cloud_map.json").read_text(encoding="utf-8"))
        group_map = json.loads((HERE / "group_map.json").read_text(encoding="utf-8"))
        rule = json.loads((HERE / "claims_rule.entra.json").read_text(encoding="utf-8"))
        graph = FakeGraph()

        def sync():
            snap = entra.fetch(token="fake-graph-token", transport=graph)
            return directory.sync(snap, bundle / "entities.json", user_id="id", group_map=group_map, force=first[0])

        print("1. Directory sync: users and groups from (fake) Microsoft Graph -> entities.json")
        first = [True]   # the very first sync replaces the example users with the directory's: that is a mass removal, hence force
        r = sync()
        first[0] = False
        print(f"   {r['users']} users, {r['groups']} groups written; agents kept; entities.sync.json says synced_at {r['synced_at']}")

        with core.open_engine(bundle, work / "state") as iam:
            print("\n2. Alice signs in. Her (verified) Entra ID token carries group object ids")
            id_token_claims = {"oid": ALICE, "preferred_username": "alice@example.com", "groups": [SUPPORT, "99999999-9999-9999-9999-999999999999"]}
            groups = claims.groups_from_claims(id_token_claims, rule)
            print(f"   claims.groups_from_claims -> {groups}   (the unknown group id is dropped)")
            grant = core.delegate(iam, user=id_token_claims["oid"], agent="support-bot", role="report-reader", task="ticket-7", groups=groups)
            print(f"   core.delegate(role='report-reader') -> token {grant.token_id}: {grant.capability.actions} on {grant.capability.resources}")

            print("\n3. The agent needs S3. An STS session bounded by that token:")
            role = {r.name: r for r in core.roles(iam)}["report-reader"]
            request = aws.assume_role_request(grant, None, cloud_map, role.bindings["aws"]["role_arn"])
            policy = json.loads(request["Policy"])
            print(f"   RoleArn          {request['RoleArn']}")
            print(f"   RoleSessionName  {request['RoleSessionName']}")
            print(f"   DurationSeconds  {request['DurationSeconds']}")
            print(f"   Tags             {{{', '.join(t['Key'] + '=' + t['Value'] for t in request['Tags'])}}}")
            print(f"   Policy           {request['Policy']}")
            aws.assume_role(request, FakeSts())   # with boto3: aws.assume_role(request, boto3.client("sts"))
            checks = [("s3:GetObject", "arn:aws:s3:::crm-exports/reports/2024/q1.csv", True),
                      ("s3:GetObject", "arn:aws:s3:::crm-exports/hr/salaries.csv", False),
                      ("s3:PutObject", "arn:aws:s3:::crm-exports/reports/2024/q1.csv", False),
                      ("s3:ListBucket", "arn:aws:s3:::crm-exports", False)]
            for action, arn, expected in checks:
                got = iam_allows(policy, action, arn)
                assert got == expected, (action, arn, got)
                print(f"   {'allowed' if got else 'denied '}  {action:<13} {arn}")
            print("   -> as mapped by cloud_map.json, the session policy grants what the token grants (read on reports/*), no more")

            sub = core.narrow(iam, grant, actor="summarizer", ttl=300, capability={"actions": ["read"], "resources": ["s3.object/reports/2024/*"]})
            sub_policy = json.loads(aws.assume_role_request(sub, None, cloud_map, role.bindings["aws"]["role_arn"])["Policy"])
            assert iam_allows(sub_policy, "s3:GetObject", "arn:aws:s3:::crm-exports/reports/2024/q1.csv")
            assert not iam_allows(sub_policy, "s3:GetObject", "arn:aws:s3:::crm-exports/reports/2023/q4.csv")
            print(f"   a sub-agent's narrower token gives a narrower policy: {sub_policy['Statement'][0]['Resource']}")

            print("\n4. Alice is removed from the Support group in the directory")
            graph.groups[SUPPORT][1].discard(ALICE)
            r = sync()
            iam.call("reload", {})          # a running engine sees the new entities.json only after a reload
            print(f"   sync: {r['diff']['membership_changed']}")
            print(f"   the token from step 2 is still alive: valid={iam.inspect_token(grant.token)['valid']}")
            revoked = directory.revoke_changed(iam, r["diff"], by="walkthrough")   # what `bridge sync-* --revoke` does
            print(f"   revoke-by-user for everyone who was removed or lost a group: {revoked['revoked']}")
            for label, token in (("the token issued before the removal", grant.token), ("its sub-agent's token", sub.token)):
                state = iam.inspect_token(token)
                assert state == {"ok": True, "valid": False, "reason": "token_revoked", "detail": state.get("detail")}, state
                print(f"   {label}: refused, {rule_id(state['reason'])}")
            print("   (the STS session from step 3 is NOT ended by this: it lives until its own expiry)")
            attempts = [("stored membership (no ID token at hand)", None),
                        ("a fresh sign-in (the new ID token no longer lists the group)", [])]
            for label, live in attempts:
                try:
                    core.delegate(iam, user=ALICE, agent="support-bot", role="report-reader", task="ticket-8", groups=live)
                    print(f"   {label}: ISSUED - this must not happen")
                    return 1
                except EngineError as e:
                    assert e.code == "role_not_held", e
                    print(f"   {label}: refused, {rule_id(e.code)}")
            print("\n   Caveat, shown on purpose: live membership passed as `groups` replaces the stored one.")
            print("   Replaying the OLD claims still works until that ID token expires:")
            stale = core.delegate(iam, user=ALICE, agent="support-bot", role="report-reader", task="ticket-9", groups=groups)
            print(f"   stale claims -> token {stale.token_id} issued. Check the ID token's exp, keep it short,")
            print("   or do not pass `groups` and rely on the synced entities.json. See docs/BRIDGES.md, Freshness.")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
