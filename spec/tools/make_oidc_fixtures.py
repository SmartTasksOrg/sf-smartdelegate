"""Regenerates conformance/oidc/*: a throwaway RSA key pair published as a
JWKS, and ID tokens signed with it. Test material only; the private key is
discarded. Needs the `cryptography` package."""
import base64, json, pathlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

out = pathlib.Path(__file__).resolve().parent.parent / "conformance" / "oidc"
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
num = lambda n: b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))

def jwt(key, kid, claims):
    head = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}).encode())
    body = b64(json.dumps(claims).encode())
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64(sig)}"

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = key.public_key().public_numbers()
(out / "jwks.json").write_text(json.dumps({"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-1", "n": num(pub.n), "e": num(pub.e)}]}, indent=1))
base = {"iss": "https://idp.example.test", "aud": "smartdelegate-demo", "iat": 1700000000, "exp": 4102444800}
tokens = {
    "alice": jwt(key, "test-1", {**base, "sub": "alice"}),
    "dave": jwt(key, "test-1", {**base, "sub": "dave"}),
    "expired": jwt(key, "test-1", {**base, "sub": "alice", "exp": 1000}),
    "wrong_audience": jwt(key, "test-1", {**base, "sub": "alice", "aud": "someone-else"}),
    "wrong_issuer": jwt(key, "test-1", {**base, "sub": "alice", "iss": "https://evil.example.test"}),
    "forged": jwt(other, "test-1", {**base, "sub": "alice"}),
    # group claims, as an identity provider sends them (its own names, mapped by idp.group_map)
    "alice_support": jwt(key, "test-1", {**base, "sub": "alice", "groups": ["sg-support"]}),
    "alice_removed": jwt(key, "test-1", {**base, "sub": "alice", "groups": []}),
    "dave_support": jwt(key, "test-1", {**base, "sub": "dave", "groups": ["sg-support"]}),
    "bob_both": jwt(key, "test-1", {**base, "sub": "bob", "groups": ["sg-supervisors", "sg-unmapped", "sg-support", "sg-support"]}),
    "carol_string": jwt(key, "test-1", {**base, "sub": "carol", "groups": "sg-compliance"}),
    "alice_malformed": jwt(key, "test-1", {**base, "sub": "alice", "groups": [1, 2]}),
    # authorised party (0.3): tokens issued to another client are refused
    "alice_azp_ours": jwt(key, "test-1", {**base, "sub": "alice", "azp": base["aud"]}),
    "alice_azp_other": jwt(key, "test-1", {**base, "sub": "alice", "aud": ["other-client", base["aud"]], "azp": "other-client"}),
    "alice_azp_other_single": jwt(key, "test-1", {**base, "sub": "alice", "azp": "other-client"}),
    "alice_multi_aud_no_azp": jwt(key, "test-1", {**base, "sub": "alice", "aud": ["other-client", base["aud"]]}),
    "alice_multi_aud_ours": jwt(key, "test-1", {**base, "sub": "alice", "aud": [base["aud"], "account"], "azp": base["aud"]}),
    # sign-ins at known times, for the revoke cut-off
    "alice_iat_plus3": jwt(key, "test-1", {**base, "sub": "alice", "iat": 1700000003}),
    "alice_iat_plus9": jwt(key, "test-1", {**base, "sub": "alice", "iat": 1700000009}),
    "alice_no_iat": jwt(key, "test-1", {k: v for k, v in {**base, "sub": "alice"}.items() if k != "iat"}),
    # a nested claim, as Keycloak's realm roles mapper writes it
    "bob_nested": jwt(key, "test-1", {**base, "sub": "bob", "realm_access": {"roles": ["sg-supervisors", "sg-support", "offline_access"]}}),
    "alice_nested_missing": jwt(key, "test-1", {**base, "sub": "alice", "realm_access": {}}),
}
(out / "id_tokens.json").write_text(json.dumps(tokens, indent=1))

# The same material as conformance vectors, so every port runs it the same way.
jwks = json.loads((out / "jwks.json").read_text())
T = 1700000000
CAP = {"actions": ["read"], "resources": ["crm.customer/*"]}
idp = {"issuer": base["iss"], "audience": base["aud"], "jwks": jwks}
err = lambda code: {"ok": False, "error": {"code": code}}
def issue(tok, expect, save=None, **kw):
    s = {"op": "issue_token", "input": {"id_token": tokens[tok], "agent": "support-bot", "now": T, **kw}, "expect": expect}
    if save:
        s["save"] = save
    return s
vectors = out.parent / "vectors"
(vectors / "08_oidc.json").write_text(json.dumps({
    "suite": "08_oidc",
    "about": "ID tokens from an OIDC provider name the user. `config` is merged into the conformance configuration. Regenerate with spec/tools/make_oidc_fixtures.py.",
    "config": {"idp": idp},
    "cases": [
        {"name": "a verified ID token names the user", "steps": [
            issue("alice", {"ok": True, "user": "alice"}, cap=CAP),
            issue("alice", {"ok": True, "user": "alice"}, cap=CAP, user="alice"),
            issue("alice", {"ok": True, "role": "support-agent"}, role="support-agent"),
        ]},
        {"name": "policy still applies to a verified user", "steps": [
            issue("dave", err("delegation_denied"), cap=CAP),
            issue("dave", err("role_not_held"), role="support-agent"),
        ]},
        {"name": "bad ID tokens are refused", "steps": [
            issue("expired", err("id_token_invalid"), cap=CAP),
            issue("wrong_audience", err("id_token_invalid"), cap=CAP),
            issue("wrong_issuer", err("id_token_invalid"), cap=CAP),
            issue("forged", err("id_token_invalid"), cap=CAP),
            {"op": "issue_token", "input": {"id_token": "not.a.jwt", "agent": "support-bot", "cap": CAP, "now": T}, "expect": err("id_token_invalid")},
        ]},
        {"name": "a token issued to another client is not an ID token for this one", "steps": [
            issue("alice_azp_ours", {"ok": True}, cap=CAP),
            issue("alice_multi_aud_ours", {"ok": True}, cap=CAP),
            issue("alice_azp_other", err("id_token_invalid"), cap=CAP),
            issue("alice_azp_other_single", err("id_token_invalid"), cap=CAP),
            issue("alice_multi_aud_no_azp", err("id_token_invalid"), cap=CAP),
        ]},
        {"name": "a sign-in from before the user was revoked cannot start a new agent", "steps": [
            issue("alice_iat_plus3", {"ok": True}, cap=CAP),
            {"op": "revoke", "input": {"user": "alice", "now": T + 5}, "expect": {"ok": True}},
            {"op": "issue_token", "input": {"id_token": tokens["alice_iat_plus3"], "agent": "support-bot", "cap": CAP, "now": T + 10}, "expect": err("id_token_invalid")},
            {"op": "issue_token", "input": {"id_token": tokens["alice"], "agent": "support-bot", "cap": CAP, "now": T + 10}, "expect": err("id_token_invalid")},
            {"op": "issue_token", "input": {"id_token": tokens["alice_no_iat"], "agent": "support-bot", "cap": CAP, "now": T + 10}, "expect": err("id_token_invalid")},
            {"op": "issue_token", "input": {"id_token": tokens["alice_iat_plus9"], "agent": "support-bot", "cap": CAP, "now": T + 10}, "expect": {"ok": True}, "save": {"t": "token"}},
            {"op": "authorize", "input": {"token": "$t", "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}, "now": T + 11}, "expect": {"ok": True, "effect": "allow"}},
            {"op": "issue_token", "input": {"id_token": tokens["dave"], "agent": "support-bot", "cap": CAP, "now": T + 10}, "expect": err("delegation_denied")},
        ]},
        {"name": "without a groups claim configured, group claims in the ID token are ignored", "steps": [
            issue("alice_removed", {"ok": True}, save={"t": "token"}, role="support-agent"),
            {"op": "inspect_token", "input": {"token": "$t", "now": T}, "expect": {"ok": True, "valid": True, "claims": {"grp": None}}},
        ]},
    ]}, indent=1))
(vectors / "09_oidc_groups.json").write_text(json.dumps({
    "suite": "09_oidc_groups",
    "about": "With idp.groups_claim set, the identity provider is the authority on what the human is a member of right now. Regenerate with spec/tools/make_oidc_fixtures.py.",
    "config": {"idp": {**idp, "groups_claim": "groups",
                       "group_map": {"sg-support": "support", "sg-supervisors": "supervisors", "sg-compliance": "compliance", "sg-ghost": "no-such-group"}}},
    "cases": [
        {"name": "the provider's groups decide which roles the human can lend", "steps": [
            issue("alice_support", {"ok": True, "role": "support-agent"}, save={"t": "token"}, role="support-agent"),
            {"op": "inspect_token", "input": {"token": "$t", "now": T}, "expect": {"ok": True, "valid": True, "claims": {"grp": [{"type": "Group", "id": "support"}]}}},
            issue("alice_support", err("role_not_held"), role="supervisor", task="escalation-1"),
        ]},
        {"name": "a human removed from a group at the provider loses the role at once", "steps": [
            issue("alice_removed", err("role_not_held"), role="support-agent"),
            issue("alice_removed", err("delegation_denied"), cap=CAP),
            issue("alice", err("role_not_held"), role="support-agent"),
        ]},
        {"name": "a human added at the provider gains the role without a bundle change", "steps": [
            issue("dave_support", {"ok": True, "user": "dave"}, save={"t": "token"}, role="support-agent"),
            {"op": "authorize", "input": {"token": "$t", "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}, "now": T},
             "expect": {"ok": True, "effect": "allow", "principal": {"user": "dave", "role": "support-agent"}}},
        ]},
        {"name": "provider group names are mapped; unmapped and unknown ones are dropped", "steps": [
            issue("bob_both", {"ok": True, "role": "supervisor"}, save={"t": "token"}, role="supervisor", task="escalation-1"),
            {"op": "inspect_token", "input": {"token": "$t", "now": T},
             "expect": {"ok": True, "valid": True, "claims": {"grp": [{"type": "Group", "id": "supervisors"}, {"type": "Group", "id": "support"}]}}},
            issue("carol_string", {"ok": True, "role": "auditor"}, role="auditor"),
            issue("alice_malformed", err("id_token_invalid"), role="support-agent"),
        ]},
        {"name": "groups passed by the caller are ignored when an ID token is presented", "steps": [
            issue("alice_removed", err("role_not_held"), role="support-agent", groups=["support"]),
        ]},
    ]}, indent=1))
(vectors / "12_oidc_nested_claim.json").write_text(json.dumps({
    "suite": "12_oidc_nested_claim",
    "about": "idp.groups_claim may be a dotted path into the ID token (Keycloak writes realm roles to realm_access.roles). A top-level claim with that exact name wins. Regenerate with spec/tools/make_oidc_fixtures.py.",
    "config": {"idp": {**idp, "groups_claim": "realm_access.roles",
                       "group_map": {"sg-support": "support", "sg-supervisors": "supervisors"}}},
    "cases": [
        {"name": "group membership is read from a nested claim", "steps": [
            issue("bob_nested", {"ok": True, "role": "supervisor"}, save={"t": "token"}, role="supervisor", task="escalation-1"),
            {"op": "inspect_token", "input": {"token": "$t", "now": T},
             "expect": {"ok": True, "valid": True, "claims": {"grp": [{"type": "Group", "id": "supervisors"}, {"type": "Group", "id": "support"}]}}},
            issue("alice_nested_missing", err("role_not_held"), role="support-agent"),
            issue("alice", err("role_not_held"), role="support-agent"),
        ]},
    ]}, indent=1))
print("wrote", out, "and", vectors)
