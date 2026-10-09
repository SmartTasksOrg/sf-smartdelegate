"""sf_smartdelegate.bridges, tested against fakes only.

Nothing in this file talks to AWS, Azure, Google, Okta or Keycloak. The
directory adapters run against in-process fake servers
(bridges_fixtures/fakes.py) written from the providers' documentation; the
cloud generators are checked on their output with an independent evaluator
written here. The only sockets are loopback ones: one test class runs the
default urllib transport against a local http.server.
"""
import datetime
import http.server
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from support import BUNDLE, CLI, ENV, ROOT, Daemon, conformance_config

sys.path.insert(0, str(Path(__file__).parent / "bridges_fixtures"))
import fakes  # noqa: E402

from sf_smartdelegate import DaemonClient, Engine, core, tokens  # noqa: E402
from sf_smartdelegate.bridges import (BridgeError, aws, aws_identity_center, azure, ceiling, claims, cloudmap, directory, entra, gcp,  # noqa: E402
                                   google, keycloak, okta, scim, sigv4)
from sf_smartdelegate.bridges import cli as bridge_cli  # noqa: E402
from sf_smartdelegate.bridges import http as bhttp  # noqa: E402
from sf_smartdelegate.bridges.directory import Group, Snapshot, User  # noqa: E402
from sf_smartdelegate.errors import EngineError  # noqa: E402

ENVV = {"TOK": fakes.TOKEN, "AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "AWS_SESSION_TOKEN": "session-token"}


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="smartdelegate-bridges-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def raises(self, code, fn, *a, **kw):
        with self.assertRaises(BridgeError) as cm:
            fn(*a, **kw)
        self.assertEqual(cm.exception.code, code, cm.exception)
        self.assertNotIn(fakes.TOKEN, str(cm.exception))
        return cm.exception


# ---- http ------------------------------------------------------------------------

class HttpHelpers(Tmp):
    def test_link_header(self):
        h = {"link": '<https://a.example/x?after=1>; rel="self", <https://a.example/x?after=2>; rel="next"'}
        self.assertEqual(bhttp.link_next(h), "https://a.example/x?after=2")
        self.assertIsNone(bhttp.link_next({"link": '<https://a.example/x>; rel="self"'}))
        self.assertIsNone(bhttp.link_next({}))

    def test_page_guard(self):
        g = bhttp.PageGuard("https://a.example/x", max_pages=3)
        g.step("a")
        self.raises("pagination_loop", g.step, "a")
        g.step("b")
        self.raises("pagination_limit", g.step, "c")
        self.assertEqual(g.check_next("https://a.example/y"), "https://a.example/y")
        for bad in ("https://b.example/x", "http://a.example/x", "https://a.example:8443/x", "//b.example/x"):
            self.raises("next_link_refused", g.check_next, bad)
        self.raises("malformed_response", g.check_next, 7)

    def test_plain_http_is_refused_except_loopback(self):
        self.raises("insecure_url", bhttp.check_url, "http://idp.example/scim")
        self.raises("bad_url", bhttp.check_url, "ftp://idp.example/")
        bhttp.check_url("http://127.0.0.1:8080/x")
        bhttp.check_url("https://idp.example/x")

    def test_secret_from_env(self):
        self.assertEqual(bhttp.secret_from_env("TOK", ENVV), fakes.TOKEN)
        e = self.raises("no_credential", bhttp.secret_from_env, "NOPE", ENVV)
        self.assertIn("NOPE", e.message)
        self.raises("no_credential", bhttp.secret_from_env, "", ENVV)

    def test_errors_carry_no_secret_and_no_body(self):
        def t(method, url, headers, body):
            return 403, {}, ("denied for " + headers["Authorization"]).encode()
        e = self.raises("http_error", bhttp.get_json, t, "https://a.example/x?token=" + fakes.TOKEN, bhttp.bearer(fakes.TOKEN))
        self.assertEqual(e.detail, {"status": 403})
        self.assertNotIn("denied", e.message)

        def boom(method, url, headers, body):
            raise RuntimeError("could not send " + headers["Authorization"])
        self.raises("network", bhttp.get_json, boom, "https://a.example/x", bhttp.bearer(fakes.TOKEN))


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        other = self.server.other
        if self.path == "/ok":
            body = json.dumps({"auth": self.headers.get("Authorization")}).encode()
            self.send_response(200)
        elif self.path == "/fail":
            body = b'{"error": "boom"}'
            self.send_response(500)
        elif self.path == "/same":
            body = b""
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/ok")
        elif self.path == "/away":
            body = b""
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{other}/ok")
        elif self.path == "/slow":
            self.server.release.wait(5)
            body = b"{}"
            self.send_response(200)
        else:
            body = b"{}"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Quiet(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):   # a client that timed out on purpose is not news
        pass


class UrllibTransport(Tmp):
    """The default transport against a loopback http.server (the only sockets in this file)."""

    def setUp(self):
        super().setUp()
        self.server = _Quiet(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        self.server.other, self.server.release = self.server.server_port + 1, threading.Event()
        t = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.release.set)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        clean = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
        p = mock.patch.dict(os.environ, clean, clear=True)
        p.start()
        self.addCleanup(p.stop)
        self.transport = bhttp.make_transport(timeout=3)

    def test_get_json_and_error_status(self):
        v, _ = bhttp.get_json(self.transport, self.base + "/ok", bhttp.bearer(fakes.TOKEN))
        self.assertEqual(v, {"auth": "Bearer " + fakes.TOKEN})
        status, headers, body = self.transport("GET", self.base + "/fail", {}, None)
        self.assertEqual((status, json.loads(body)), (500, {"error": "boom"}))
        self.raises("http_error", bhttp.get_json, self.transport, self.base + "/fail")

    def test_redirects(self):
        v, _ = bhttp.get_json(self.transport, self.base + "/same", bhttp.bearer(fakes.TOKEN))
        self.assertEqual(v["auth"], "Bearer " + fakes.TOKEN)
        e = self.raises("redirect_refused", bhttp.get_json, self.transport, self.base + "/away", bhttp.bearer(fakes.TOKEN))
        self.assertIn("localhost", e.message)

    def test_timeout_and_unreachable(self):
        quick = bhttp.make_transport(timeout=0.3)
        self.raises("network", quick, "GET", self.base + "/slow", {}, None)
        self.raises("insecure_url", quick, "GET", "http://idp.example/x", {}, None)


# ---- claims ----------------------------------------------------------------------

class Claims(Tmp):
    G1, G2 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"

    def test_entra_groups_roles_wids(self):
        c = {"oid": "o1", "groups": [self.G2, self.G1, self.G1], "roles": ["Refund.Approver"], "wids": ["w-1"]}
        rule = {"provider": "entra", "map": {self.G1: "support", self.G2: "supervisors"}}
        self.assertEqual(claims.groups_from_claims(c, rule), ["supervisors", "support"])
        self.assertEqual(claims.groups_from_claims(c, {"provider": "entra"}), sorted([self.G1, self.G2]))
        rule = {"provider": "entra", "sources": ["groups", "roles", "wids"], "map": {"roles:Refund.Approver": "supervisors", "wids:w-1": "compliance"}}
        self.assertEqual(claims.groups_from_claims(c, rule), ["compliance", "supervisors"])
        # an app role named like a group id is not a group
        self.assertEqual(claims.groups_from_claims({"roles": [self.G1]}, {"provider": "entra", "sources": ["groups", "roles"], "map": {self.G1: "support"}}), [])
        self.assertEqual(claims.groups_from_claims({"oid": "o1"}, rule), [])
        self.assertEqual(claims.groups_from_claims(c, {"provider": "entra", "map": {self.G1: "support"}, "unmapped": "keep"}), sorted([self.G2, "support"]))

    def test_entra_overage(self):
        rule = {"provider": "entra", "map": {self.G1: "support"}}
        for c in ({"_claim_names": {"groups": "src1"}, "_claim_sources": {"src1": {"endpoint": "https://graph.windows.net/x"}}},
                  {"_claim_names": '{"groups":"src1"}'}, {"hasgroups": True}, {"hasgroups": "true"},
                  {"groups": [self.G1], "_claim_names": {"groups": "src1"}}):
            e = self.raises("claims_overage", claims.groups_from_claims, c, rule)
            self.assertIn("member_groups", e.message)
        # resolved through Graph (fake), then mapped like a claim
        ids = entra.member_groups("u3", token=fakes.TOKEN, transport=fakes.Graph())
        self.assertEqual(ids, ["g1", "g3"])
        self.assertEqual(claims.groups_from_claims({"groups": ids}, {"provider": "generic", "claim": "groups", "map": {"g1": "support"}}), ["support"])
        self.raises("truncated_pagination", entra.member_groups, "u3", token=fakes.TOKEN, transport=fakes.Graph(mode="truncated"))
        self.raises("http_error", entra.member_groups, "u3", token=fakes.TOKEN, transport=fakes.Graph(mode="http500"))
        # roles only: an overage of groups does not matter
        self.assertEqual(claims.groups_from_claims({"hasgroups": True, "roles": ["r"]}, {"provider": "entra", "sources": ["roles"]}), ["roles:r"])

    def test_keycloak_paths_and_roles(self):
        c = {"groups": ["/support/eu", "/compliance"], "realm_access": {"roles": ["offline_access", "auditor"]},
             "resource_access": {"crm": {"roles": ["refunds"]}, "other": {"roles": ["x"]}}}
        k = lambda **r: claims.groups_from_claims(c, {"provider": "keycloak", **r})
        self.assertEqual(k(), ["/compliance", "/support/eu"])
        self.assertEqual(k(group_paths="strip"), ["compliance", "support/eu"])
        self.assertEqual(k(group_paths="leaf"), ["compliance", "eu"])
        self.assertEqual(k(group_paths="expand"), ["/compliance", "/support", "/support/eu"])
        self.assertEqual(k(group_paths="expand", map={"/support": "support"}), ["support"])
        self.assertEqual(k(sources=["realm_roles"]), ["realm_roles:auditor", "realm_roles:offline_access"])
        self.assertEqual(k(sources=["client_roles"], client="crm"), ["client_roles:refunds"])
        self.assertEqual(k(sources=["client_roles"], client="absent"), [])
        self.raises("rule_invalid", k, sources=["client_roles"])
        self.raises("rule_invalid", k, group_paths="shortest")

    # Claim sets as a real Keycloak 26.0.7 issued them (live/idp/, 2026-10-05; ids shortened).
    # The user is a direct member of /employees/managers and /employees/support/support-supervisors.
    KC_ID = {"exp": 1791213251, "iat": 1791212951, "jti": "c74035d9", "iss": "http://127.0.0.1:50237/realms/kestrel", "aud": "sd-engine",
             "sub": "e4c44289-3302-4b91-9170-b693dcbf3b08", "typ": "ID", "azp": "sd-engine", "sid": "4c8cdc39", "at_hash": "JEUhGdxuY1G_C56ePlAMWg",
             "acr": "1", "email_verified": True, "name": "Elena Rossi", "preferred_username": "elena", "given_name": "Elena",
             "family_name": "Rossi", "email": "elena@kestrel.example",
             "groups": ["/employees/managers", "/employees/support/support-supervisors"]}
    KC_ACCESS = {**{k: v for k, v in KC_ID.items() if k != "at_hash"}, "typ": "Bearer", "aud": ["sd-engine-roles", "account"],
                 "allowed-origins": ["http://127.0.0.1"], "scope": "openid email profile",
                 "realm_access": {"roles": ["support-supervisors", "offline_access", "uma_authorization", "default-roles-kestrel", "employees", "support", "managers"]},
                 "resource_access": {"sd-engine-roles": {"roles": ["refund-approver"]}, "account": {"roles": ["manage-account", "manage-account-links", "view-profile"]}}}

    def test_keycloak_real_token_shapes(self):
        k = lambda c, **r: claims.groups_from_claims(c, {"provider": "keycloak", **r})
        # the groups claim lists DIRECT groups only: the parents /employees and /employees/support are not in it
        self.assertEqual(k(self.KC_ID), ["/employees/managers", "/employees/support/support-supervisors"])
        self.assertEqual(k(self.KC_ID, group_paths="expand"),
                         ["/employees", "/employees/managers", "/employees/support", "/employees/support/support-supervisors"])
        gm = {"/employees/support": "support", "/employees/managers": "managers"}
        self.assertEqual(k(self.KC_ID, map=gm), ["managers"])                              # without expand: not in support
        self.assertEqual(k(self.KC_ID, map=gm, group_paths="expand"), ["managers", "support"])
        # an ID token has no realm_access / resource_access: reading roles from it gives nothing (never everything)
        self.assertEqual(k(self.KC_ID, sources=["realm_roles"]), [])
        self.assertEqual(k(self.KC_ID, sources=["client_roles"], client="sd-engine-roles"), [])
        # the access token has them; realm roles include those inherited from parent groups and the realm defaults
        self.assertEqual(k(self.KC_ACCESS, sources=["realm_roles"], map={"realm_roles:support": "support", "realm_roles:employees": "employees"}),
                         ["employees", "support"])
        self.assertEqual(k(self.KC_ACCESS, sources=["client_roles"], client="sd-engine-roles"), ["client_roles:refund-approver"])
        # a "User Realm Role" mapper writing a flat claim into the ID token
        flat = {**self.KC_ID, "roles": ["support-supervisors", "default-roles-kestrel", "support"]}
        del flat["groups"]
        self.assertEqual(k(flat, sources=["realm_roles"], roles_claim="roles", map={"realm_roles:support": "support"}), ["support"])
        self.assertEqual(k(flat, sources=["realm_roles"]), [])                              # not at realm_access.roles
        self.assertEqual(k(flat), [])                                                       # a user in no group has NO groups claim
        self.raises("rule_invalid", k, flat, roles_claim="")
        self.raises("rule_invalid", claims.groups_from_claims, flat, {"provider": "okta", "roles_claim": "roles"})

    def test_keycloak_bare_group_names(self):
        """"Full group path" off: the claim holds names, not paths. A name may contain a slash."""
        c = {"groups": ["managers", "support-supervisors", "eu/west"]}
        k = lambda **r: claims.groups_from_claims(c, {"provider": "keycloak", **r})
        self.assertEqual(k(), ["eu/west", "managers", "support-supervisors"])
        self.assertEqual(k(map={"managers": "managers"}), ["managers"])
        for mode in ("strip", "leaf", "expand"):      # taking a bare name apart would invent groups ("west", "/managers")
            e = self.raises("claims_invalid", k, group_paths=mode)
            self.assertIn("Full group path", e.message)
        self.assertEqual(claims.groups_from_claims({"groups": ["/", ""]}, {"provider": "keycloak"}), [])

    def test_other_presets(self):
        g = claims.groups_from_claims
        self.assertEqual(g({"groups": ["Everyone", "Support"]}, {"provider": "okta", "map": {"Support": "support"}}), ["support"])
        self.assertEqual(g({"groups": "Support"}, {"provider": "okta"}), ["Support"])
        self.assertEqual(g({"cognito:groups": ["support"]}, {"provider": "cognito"}), ["support"])
        ns = "https://example.com/groups"
        self.assertEqual(g({ns: ["b", "a"]}, {"provider": "auth0", "claim": ns}), ["a", "b"])
        self.raises("rule_invalid", g, {}, {"provider": "auth0"})
        self.assertEqual(g({"a": {"b": ["x"]}}, {"provider": "generic", "claim": "a.b"}), ["x"])
        self.assertEqual(g({"a.b": ["y"], "a": {"b": ["x"]}}, {"provider": "generic", "claim": "a.b"}), ["y"])
        self.assertEqual(g({}, {"provider": "generic", "claim": "a.b"}), [])
        e = self.raises("claims_no_groups", g, {"hd": "example.com"}, {"provider": "google"})
        self.assertIn("no groups", e.message)
        self.assertEqual(g({"hd": "example.com"}, {"provider": "google", "map": {"hd:example.com": "employees"}}), ["employees"])
        self.assertEqual(g({"hd": "other.org"}, {"provider": "google", "map": {"hd:example.com": "employees"}, "unmapped": "keep"}), [])

    def test_bad_input_fails_closed(self):
        g = claims.groups_from_claims
        self.raises("claims_invalid", g, {"groups": [{"id": "x"}]}, {"provider": "okta"})
        self.raises("claims_invalid", g, {"groups": 7}, {"provider": "entra"})
        self.raises("rule_invalid", g, {}, {"provider": "okta", "mapp": {}})
        self.raises("rule_invalid", g, {}, {"provider": "ldap"})
        self.raises("rule_invalid", g, {}, {"provider": "okta", "unmapped": "all"})
        self.raises("rule_invalid", g, {}, {"provider": "okta", "map": {"a": ["x"]}})
        self.raises("rule_invalid", g, {}, {"provider": "okta", "sources": ["groups"]})


# ---- SigV4 -----------------------------------------------------------------------

class SigV4(Tmp):
    """The worked examples of https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html"""
    KEYS = dict(access_key="AKIAIOSFODNN7EXAMPLE", secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", region="us-east-1", service="s3",
                now=datetime.datetime(2013, 5, 24, tzinfo=datetime.timezone.utc))
    EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def signature(self, url, headers):
        out = sigv4.sign("GET", url, headers, b"", **self.KEYS)
        self.assertNotIn(self.KEYS["secret_key"], json.dumps(out))
        return out["Authorization"]

    def test_get_object(self):
        a = self.signature("https://examplebucket.s3.amazonaws.com/test.txt", {"Range": "bytes=0-9", "x-amz-content-sha256": self.EMPTY})
        self.assertEqual(a, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
                            "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"
                            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")

    def test_get_bucket_lifecycle(self):
        a = self.signature("https://examplebucket.s3.amazonaws.com/?lifecycle", {"x-amz-content-sha256": self.EMPTY})
        self.assertTrue(a.endswith("Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"), a)

    def test_list_objects(self):
        a = self.signature("https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", {"x-amz-content-sha256": self.EMPTY})
        self.assertTrue(a.endswith("Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"), a)

    def test_canonical_request_text(self):
        canon, signed = sigv4.canonical_request("GET", "https://examplebucket.s3.amazonaws.com/?prefix=J&max-keys=2",
                                                {"Host": "examplebucket.s3.amazonaws.com", "X-Amz-Date": "20130524T000000Z",
                                                 "x-amz-content-sha256": self.EMPTY}, b"")
        self.assertEqual(canon, "GET\n/\nmax-keys=2&prefix=J\nhost:examplebucket.s3.amazonaws.com\n"
                                f"x-amz-content-sha256:{self.EMPTY}\nx-amz-date:20130524T000000Z\n\n"
                                f"host;x-amz-content-sha256;x-amz-date\n{self.EMPTY}")

    def test_session_token_is_signed_and_keys_are_required(self):
        out = sigv4.sign("POST", "https://identitystore.eu-west-1.amazonaws.com/", {"X-Amz-Target": "X.Y"}, b"{}", access_key="A", secret_key="S",
                         region="eu-west-1", service="identitystore", session_token="T", now=self.KEYS["now"])
        self.assertIn("SignedHeaders=host;x-amz-date;x-amz-security-token;x-amz-target", out["Authorization"])
        self.raises("no_credential", sigv4.sign, "GET", "https://a.example/", {}, b"", access_key="", secret_key="", region="r", service="s")


# ---- directory adapters ----------------------------------------------------------

def names(snap, gid):
    return sorted(snap.users[u].name.split("@")[0] for u, gs in snap.memberships.items() if gid in gs)


class Adapters(Tmp):
    FETCH = {
        "scim": (fakes.Scim, lambda t: scim.fetch("https://idp.example/scim/v2", token_env="TOK", transport=t, env=ENVV, page_size=2)),
        "okta": (fakes.Okta, lambda t: okta.fetch("acme.okta.com", token_env="TOK", transport=t, env=ENVV)),
        "entra": (fakes.Graph, lambda t: entra.fetch(token_env="TOK", transport=t, env=ENVV)),
        "keycloak": (fakes.Keycloak, lambda t: keycloak.fetch("https://kc.example", "acme", token_env="TOK", transport=t, env=ENVV, page_size=2)),
        "google": (fakes.Google, lambda t: google.fetch(token_env="TOK", transport=t, env=ENVV)),
        "aws": (fakes.IdentityStore, lambda t: aws_identity_center.fetch("d-1234567890", "eu-west-1", transport=t, env=ENVV)),
    }
    NESTING = {"scim", "google"}

    def check(self, name, snap, nested):
        self.assertEqual(sorted(u.name.split("@")[0] for u in snap.users.values()), ["alice", "bob", "carol", "dave", "erin"], name)
        self.assertEqual({u.name.split("@")[0]: u.active for u in snap.users.values()},
                         {"alice": True, "bob": True, "carol": True, "dave": False, "erin": True}, name)
        self.assertEqual(sorted(snap.groups), ["g1", "g2", "g3"], name)
        self.assertEqual(names(snap, "g1"), ["alice", "bob", "erin"], name)
        self.assertEqual(names(snap, "g2"), ["bob"], name)
        self.assertEqual(names(snap, "g3"), ["carol"], name)
        self.assertEqual(snap.groups["g3"].parents, {"g1"} if nested else set(), name)
        self.assertEqual(snap.groups["g1"].parents, set(), name)

    def test_all_pages_nested_groups_inactive_users(self):
        for name, (fake, fetch) in self.FETCH.items():
            t = fake()
            snap = fetch(t)
            if name == "entra":  # transitive by default: carol is listed under support directly, no nesting recorded
                self.assertEqual(names(snap, "g1"), ["alice", "bob", "carol", "erin"])
                snap.memberships["u3"].discard("g1")
            self.check(name, snap, name in self.NESTING)
            self.assertGreaterEqual(len(t.calls), 5, f"{name}: expected several pages")
            self.assertNotIn(fakes.TOKEN, json.dumps([snap.source, [u.attrs for u in snap.users.values()]]))

    def test_http_errors_and_malformed_pages_raise(self):
        for name, (fake, fetch) in self.FETCH.items():
            for mode, code in (("http429", "http_error"), ("http500", "http_error"), ("malformed", "malformed_response")):
                with self.subTest(adapter=name, mode=mode):
                    self.raises(code, fetch, fake(mode=mode))

    def test_a_looping_next_page_stops(self):
        for name, (fake, fetch) in self.FETCH.items():
            with self.subTest(adapter=name):
                t = fake(mode="loop")
                self.raises("pagination_loop", fetch, t)
                self.assertLess(len(t.calls), 10)

    def test_a_next_link_to_another_host_is_refused(self):
        for name in ("okta", "entra"):
            fake, fetch = self.FETCH[name]
            t = fake(mode="foreign")
            e = self.raises("next_link_refused", fetch, t)
            self.assertIn("evil.example", e.message)
            self.assertEqual(len(t.calls), 1, "nothing may be sent after the foreign link")

    def test_truncated_listings_raise(self):
        self.raises("truncated_pagination", self.FETCH["scim"][1], fakes.Scim(mode="truncated"))
        self.raises("truncated_pagination", self.FETCH["keycloak"][1], fakes.Keycloak(mode="truncated"))

    def test_wrong_or_missing_credential(self):
        for name, (fake, fetch) in self.FETCH.items():
            with self.subTest(adapter=name):
                with mock.patch.dict(ENVV, {"TOK": "wrong", "AWS_SESSION_TOKEN": "wrong"}):
                    e = self.raises("http_error", fetch, fake())
                    self.assertEqual(e.detail["status"], 401)
        self.raises("no_credential", scim.fetch, "https://idp.example/scim/v2", token_env="MISSING", transport=fakes.Scim(), env=ENVV)
        self.raises("no_credential", aws_identity_center.fetch, "d-1234567890", "eu-west-1", transport=fakes.IdentityStore(), env={})
        self.raises("invalid_input", aws_identity_center.fetch, "d-1234567890", "evil.example/x", transport=fakes.IdentityStore(), env=ENVV)

    def test_scim_attributes(self):
        snap = self.FETCH["scim"][1](fakes.Scim())
        self.assertEqual(snap.users["u3"].attrs["department"], "US")
        self.assertEqual(snap.users["u1"].attrs["email"], "alice@example.com")

    def test_entra_direct_nesting_untyped_members_and_app_token(self):
        snap = entra.fetch(token=fakes.TOKEN, transport=fakes.Graph(), nested="direct")
        self.check("entra direct", snap, True)
        snap = entra.fetch(token=fakes.TOKEN, transport=fakes.Graph(with_type=False), nested="direct")
        self.check("entra untyped", snap, True)
        req = entra.token_request("contoso.onmicrosoft.com", "client-1")
        self.assertEqual(req["url"], "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token")
        self.assertEqual(req["form"], {"client_id": "client-1", "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"})
        env = {"APP_SECRET": "app-secret-value"}
        self.assertEqual(entra.acquire_token("contoso.onmicrosoft.com", "client-1", secret_env="APP_SECRET", transport=fakes.EntraLogin(), env=env), fakes.TOKEN)
        with self.assertRaises(BridgeError) as cm:
            entra.acquire_token("contoso.onmicrosoft.com", "client-1", secret_env="APP_SECRET", transport=fakes.EntraLogin("other"), env=env)
        self.assertEqual(cm.exception.code, "http_error")
        self.assertNotIn("app-secret-value", str(cm.exception))
        self.raises("invalid_input", entra.token_url, "contoso/../evil")

    def test_keycloak_paths_and_children_endpoint(self):
        for children in (False, True):
            fetch = lambda **kw: keycloak.fetch("https://kc.example", "acme", token_env="TOK", env=ENVV, page_size=2,
                                                transport=fakes.Keycloak(children_endpoint=children), **kw)
            snap = fetch(inherit=True)
            self.check(f"keycloak children={children}", snap, True)
            self.check(f"keycloak children={children}, no inheritance", fetch(), False)   # the default: a subgroup member is not in the parent
            self.assertEqual({g.name for g in snap.groups.values()}, {"/support", "/supervisors", "/support/emea"})
            self.assertEqual(snap.users["u1"].attrs["region"], "EU")
        # Keycloak 26 sends "subGroups": [] with subGroupCount 1: the child must come from /children, not be lost
        t = fakes.Keycloak()
        keycloak.fetch("https://kc.example", "acme", token_env="TOK", env=ENVV, transport=t)
        self.assertTrue(any(u.endswith("/groups/g1/children?first=0&max=100") for _, u in t.calls), t.calls)

    def test_keycloak_empty_listing_is_not_an_empty_realm(self):
        """Without view-users a real Keycloak answers 200, [] and a count of 0 (never 403)."""
        t = fakes.Keycloak(mode="underprivileged")
        e = self.raises("empty_directory", keycloak.fetch, "https://kc.example", "acme", token_env="TOK", env=ENVV, transport=t)
        self.assertIn("view-users", e.message)
        self.assertFalse(any("/groups" in u for _, u in t.calls), "nothing more is read once the user listing is empty")
        # Keycloak 26.8.0 still reports the real count for such a credential: refused as a truncated listing
        self.raises("truncated_pagination", keycloak.fetch, "https://kc.example", "acme", token_env="TOK", env=ENVV,
                    transport=fakes.Keycloak(mode="underprivileged_count"))

    def test_keycloak_two_groups_with_one_path_are_refused(self):
        """A top-level group named "support/emea" has the path of the subgroup emea of support."""
        e = self.raises("ambiguous_group_path", keycloak.fetch, "https://kc.example", "acme", token_env="TOK", env=ENVV,
                        transport=fakes.Keycloak(impostor=True, members={"g1": ["u1"], "g2": [], "g3": ["u3"], "g9": ["u5"]}))
        self.assertIn("/support/emea", e.message)

    def test_keycloak_service_account_token(self):
        env = {"KC_SECRET": fakes.Keycloak.SECRET}
        t = fakes.Keycloak()
        self.assertEqual(keycloak.acquire_token("https://kc.example", "acme", "sd-sync", secret_env="KC_SECRET", transport=t, env=env), fakes.TOKEN)
        self.assertEqual(t.calls, [("POST", "https://kc.example/realms/acme/protocol/openid-connect/token")])
        with self.assertRaises(BridgeError) as cm:
            keycloak.acquire_token("https://kc.example", "acme", "sd-sync", secret_env="KC_SECRET", transport=fakes.Keycloak(), env={"KC_SECRET": "wrong-secret"})
        self.assertEqual((cm.exception.code, cm.exception.detail["status"]), ("http_error", 401))
        self.assertNotIn("wrong-secret", str(cm.exception))
        self.raises("no_credential", keycloak.acquire_token, "https://kc.example", "acme", "sd-sync", secret_env="KC_SECRET", transport=t, env={})

    def test_entra_user_without_account_enabled_is_inactive(self):
        class Partial(fakes.Graph):
            def route(self, method, u, q, body):
                status, headers, data = super().route(method, u, q, body)
                page = json.loads(data)
                for x in page.get("value", []):
                    if x.get("userPrincipalName") == "erin@example.com":
                        del x["accountEnabled"]
                return status, headers, json.dumps(page).encode()
        snap = entra.fetch(token=fakes.TOKEN, transport=Partial())
        self.assertFalse(snap.users["u5"].active)
        self.assertTrue(snap.users["u1"].active)

    def test_okta_unknown_status_is_inactive(self):
        class Odd(fakes.Okta):
            def route(self, method, u, q, body):
                status, headers, data = super().route(method, u, q, body)
                page = json.loads(data)
                for x in page:
                    if x.get("profile", {}).get("login") == "erin":
                        x["status"] = "SOMETHING_NEW"
                return status, headers, json.dumps(page).encode()
        snap = okta.fetch("https://acme.okta.com", token_env="TOK", transport=Odd(), env=ENVV)
        self.assertFalse(snap.users["u5"].active)


# ---- snapshot -> entities.json -----------------------------------------------------

def snapshot(members=None):
    t = fakes.Scim(members=members)
    return scim.fetch("https://idp.example/scim/v2", token_env="TOK", transport=t, env=ENVV)


GROUP_MAP = {"g1": "support", "supervisors": "supervisors"}


class Entities(Tmp):
    def setUp(self):
        super().setUp()
        self.bundle = Path(self.dir) / "bundle"
        shutil.copytree(BUNDLE, self.bundle)
        self.path = self.bundle / "entities.json"
        self.original = self.path.read_text(encoding="utf-8")

    def engine(self):
        e = Engine({**conformance_config(os.path.join(self.dir, "state")), "bundle_dir": str(self.bundle)})
        self.addCleanup(e.close)
        return e

    def ids(self, entities, type_):
        return sorted(e["uid"]["id"] for e in entities if e["uid"]["type"] == type_)

    def test_to_entities_keeps_agents_and_maps_groups(self):
        existing = json.loads(self.original)
        out = directory.to_entities(snapshot(), existing, group_map=GROUP_MAP, attr_map={"region": "department"})
        self.assertEqual(self.ids(out, "Agent"), self.ids(existing, "Agent"))
        self.assertEqual(self.ids(out, "AgentGroup"), ["support-agents"])
        self.assertEqual([e for e in out if e["uid"]["type"] in ("Agent", "AgentGroup")], [e for e in existing if e["uid"]["type"] in ("Agent", "AgentGroup")])
        self.assertEqual(self.ids(out, "Group"), ["supervisors", "support"])        # emea is not in the map; compliance is gone
        self.assertEqual(self.ids(out, "User"), ["alice", "bob", "carol", "erin"])  # dave is disabled
        by = {e["uid"]["id"]: e for e in out if e["uid"]["type"] == "User"}
        self.assertEqual(by["bob"]["parents"], [{"type": "Group", "id": "supervisors"}, {"type": "Group", "id": "support"}])
        self.assertEqual(by["carol"]["parents"], [{"type": "Group", "id": "support"}])  # through the dropped emea group
        self.assertEqual(by["carol"]["attrs"], {"region": "US"})
        self.assertEqual(out, directory.to_entities(snapshot(), existing, group_map=GROUP_MAP, attr_map={"region": "department"}))

    def test_nested_groups_become_parents(self):
        out = directory.to_entities(snapshot(), [])
        by = {(e["uid"]["type"], e["uid"]["id"]): e["parents"] for e in out}
        self.assertEqual(by[("Group", "emea")], [{"type": "Group", "id": "support"}])
        self.assertEqual(by[("User", "carol")], [{"type": "Group", "id": "emea"}])
        out = directory.to_entities(snapshot(), [], user_id="id", group_id="id")
        self.assertEqual(self.ids(out, "User"), ["u1", "u2", "u3", "u5"])
        out = directory.to_entities(snapshot(), [], user_id="email")
        self.assertIn("alice@example.com", self.ids(out, "User"))

    def test_to_entities_refuses_ambiguity(self):
        s = Snapshot(users={"a": User("a", "sam"), "b": User("b", "sam")})
        self.raises("duplicate_user", directory.to_entities, s, [])
        s = Snapshot(users={"a": User("a", "sam")}, memberships={"a": {"ghost"}})
        self.raises("snapshot_inconsistent", directory.to_entities, s, [])
        s = Snapshot(users={"a": User("a", "sam", attrs={"x": 1.5})})
        self.raises("attr_invalid", directory.to_entities, s, [], attr_map={"x": "x"})
        self.raises("id_missing", directory.to_entities, Snapshot(users={"a": User("a", "sam")}), [], user_id="employeeNumber")
        cyc = Snapshot(users={"a": User("a", "sam")}, groups={"x": Group("x", "x", {"y"}), "y": Group("y", "y", {"x"})}, memberships={"a": {"x"}})
        self.assertEqual(len(directory.to_entities(cyc, [], group_map={"nothing": "n"})), 1)  # a cycle of dropped groups terminates

    def test_two_directory_groups_with_one_name_are_not_merged(self):
        """Display names are not unique. A second group called "support" (id g9, member dave's
        colleague erin only) must not hand its members the first one's role."""
        twin = {"g9": ("support", ["u5"], [])}
        adapters = {"scim": lambda: scim.fetch("https://idp.example/scim/v2", token_env="TOK", transport=fakes.Scim(), env=ENVV),
                    "okta": lambda: okta.fetch("acme.okta.com", token_env="TOK", transport=fakes.Okta(), env=ENVV)}
        for name, fetch in adapters.items():
            with self.subTest(adapter=name), mock.patch.dict(fakes.GROUPS, twin):
                snap = fetch()
                self.assertEqual(sorted(g.name for g in snap.groups.values()).count("support"), 2)
                e = self.raises("duplicate_group", directory.to_entities, snap, [])                                  # identified by name
                self.assertIn("g9", e.message)
                self.raises("duplicate_group", directory.to_entities, snap, [], group_map={"support": "support"})    # mapped by name
                before = self.path.read_bytes() if self.path.exists() else None
                self.raises("duplicate_group", directory.sync, snap, self.path, group_map={"support": "support"}, force=True)
                self.assertEqual(self.path.read_bytes() if self.path.exists() else None, before, "nothing is written")
                members = lambda ents, g: sorted(x["uid"]["id"].split("@")[0] for x in ents if x["uid"]["type"] == "User"
                                                 and {"type": "Group", "id": g} in x["parents"])
                # identified by directory id: two groups, nobody merged
                by_id = directory.to_entities(snap, [], group_id="id")
                self.assertEqual((members(by_id, "g1"), members(by_id, "g9")), (["alice", "bob", "erin"], ["erin"]))
                # one of them named by id: the other is simply not mapped
                # (SCIM nests emea in support: carol, below the unmapped emea, reaches support above it)
                support = ["alice", "bob", "carol", "erin"] if name == "scim" else ["alice", "bob", "erin"]
                one = directory.to_entities(snap, [], group_map={"g1": "support"})
                self.assertEqual(members(one, "support"), support)
                only_twin = directory.to_entities(snap, [], group_map={"g9": "support"})
                self.assertEqual(members(only_twin, "support"), ["erin"])
                # both named by id: merging on purpose stays possible
                both = directory.to_entities(snap, [], group_map={"g1": "support", "g9": "support"})
                self.assertEqual(members(both, "support"), support)
                # different names mapped to one group: also on purpose, as before
                merged = directory.to_entities(snap, [], group_map={"supervisors": "staff", "emea": "staff"})
                self.assertEqual(members(merged, "staff"), ["bob", "carol"])
        # without the twin nothing changed: the same group reached by id or by name is one group
        self.assertEqual(directory.to_entities(snapshot(), [], group_map={"g1": "support", "support": "support"}),
                         directory.to_entities(snapshot(), [], group_map={"support": "support"}))

    def test_synced_entities_load_in_the_engine_and_roles_follow_membership(self):
        r = directory.sync(snapshot(), self.path, group_map=GROUP_MAP)
        self.assertTrue(r["written"])
        self.assertEqual(r["diff"]["users_removed"], ["dave"])
        e = self.engine()
        for user in ("alice", "carol"):
            g = core.delegate(e, user=user, agent="support-bot", role="support-agent", task="ticket-1")
            self.assertEqual(g.role, "support-agent")
        with self.assertRaises(EngineError) as cm:
            core.delegate(e, user="dave", agent="support-bot", role="support-agent", task="ticket-1")
        self.assertEqual(cm.exception.code, "role_not_held")
        self.assertEqual(core.delegate(e, user="bob", agent="support-bot", role="supervisor", task="escalation-1").role, "supervisor")
        with self.assertRaises(EngineError) as cm:
            core.delegate(e, user="alice", agent="support-bot", role="supervisor", task="escalation-1")
        self.assertEqual(cm.exception.code, "role_not_held")

        # alice leaves the support group in the directory; the next sync takes the role away
        members = {"g1": ["u2", "u5"], "g2": ["u2"], "g3": ["u3"]}
        r = directory.sync(snapshot(members), self.path, group_map=GROUP_MAP)
        self.assertEqual(r["diff"]["membership_changed"], [{"user": "alice", "added": [], "removed": ["Group::support"]}])
        self.assertTrue(e.call("reload", {})["ok"])
        with self.assertRaises(EngineError) as cm:
            core.delegate(e, user="alice", agent="support-bot", role="support-agent", task="ticket-2")
        self.assertEqual(cm.exception.code, "role_not_held")
        self.assertEqual(core.delegate(e, user="erin", agent="support-bot", role="support-agent", task="ticket-2").role, "support-agent")

    def test_revoke_changed_ends_tokens_of_removed_and_shrunk_users_only(self):
        directory.sync(snapshot(), self.path, group_map=GROUP_MAP)
        e = self.engine()
        tok = {u: core.delegate(e, user=u, agent="support-bot", role="support-agent", task="ticket-1") for u in ("alice", "bob", "erin")}
        sub = core.narrow(e, tok["alice"], actor="summarizer", ttl=60, capability={"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["secret"]})
        valid = lambda g: e.inspect_token(g.token).get("reason") or "valid"
        # alice leaves support, erin leaves the directory, bob gains a group, carol is untouched
        snap = snapshot({"g1": ["u2", "u5"], "g2": ["u2", "u3"], "g3": ["u3"]})
        del snap.users["u5"]
        dry = directory.sync(snap, self.path, group_map=GROUP_MAP, force=True, dry_run=True)
        self.assertEqual(directory.users_to_revoke(dry["diff"]), ["alice", "erin"])
        self.assertEqual([valid(g) for g in tok.values()], ["valid"] * 3)           # a dry run revokes nothing
        r = directory.sync(snap, self.path, group_map=GROUP_MAP, force=True)
        self.assertEqual([c["user"] for c in r["diff"]["membership_changed"]], ["alice", "carol"])   # carol only gained
        self.assertEqual(directory.revoke_changed(e, r["diff"], by="test"), {"revoked": ["alice", "erin"]})
        self.assertEqual({u: valid(g) for u, g in tok.items()}, {"alice": "token_revoked", "bob": "valid", "erin": "token_revoked"})
        self.assertEqual(valid(sub), "token_revoked")                                # the sub-agent's token goes with it
        self.assertEqual(core.check(e, tok["alice"].token, "read", "crm.customer", "c-1").reason, "token_revoked")
        self.assertNotEqual(core.check(e, tok["bob"].token, "read", "crm.customer", "c-1").reason, "token_revoked")
        rec = [x for x in e.call("audit_tail", {"n": 5})["records"] if x["event"] == "user_revoked"]
        self.assertEqual([(x["user"], x["by"]) for x in rec], [("alice", "test"), ("erin", "test")])
        self.assertEqual(directory.revoke_changed(e, {"users_added": ["zed"], "users_removed": [], "membership_changed": []}), {"revoked": []})

    def test_revoke_changed_names_exactly_who_was_not_revoked(self):
        class Flaky:
            def __init__(self):
                self.calls = []

            def call(self, op, payload):
                self.calls.append((op, payload))
                if payload["user"] == "bob":
                    return {"ok": False, "error": {"code": "state_io", "message": "disk full"}}
                if payload["user"] == "carol":
                    raise ConnectionError("daemon went away")
                return {"ok": True, "revoked_user": payload["user"], "issued_up_to": 1}
        d = {"users_removed": ["dave", "bob"], "users_added": [],
             "membership_changed": [{"user": "carol", "added": [], "removed": ["Group::x"]}, {"user": "erin", "added": ["Group::y"], "removed": []}]}
        b = Flaky()
        e = self.raises("revoke_failed", directory.revoke_changed, b, d)
        self.assertEqual(e.detail, {"revoked": ["dave"], "not_revoked": ["bob", "carol"]})
        self.assertIn("NOT revoked: bob, carol", e.message)
        self.assertEqual([c[1]["user"] for c in b.calls], ["bob", "carol", "dave"])   # every user is attempted

    def test_sidecar_and_dry_run(self):
        r = directory.sync(snapshot(), self.path, group_map=GROUP_MAP, dry_run=True)
        self.assertFalse(r["written"])
        self.assertEqual(self.path.read_text(encoding="utf-8"), self.original)
        self.assertFalse((self.bundle / "entities.sync.json").exists())
        r = directory.sync(snapshot(), self.path, group_map=GROUP_MAP)
        side = json.loads((self.bundle / "entities.sync.json").read_text())
        self.assertEqual((side["source"], side["users"], side["groups"], side["users_removed"]), ("scim:https://idp.example/scim/v2", 4, 2, 1))
        import hashlib
        self.assertEqual(side["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertRegex(side["synced_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertNotIn("synced_at", self.path.read_text())
        again = directory.sync(snapshot(), self.path, group_map=GROUP_MAP)
        self.assertEqual(again["diff"], {"users_added": [], "users_removed": [], "membership_changed": []})

    def test_removal_guard(self):
        # a directory that suddenly answers with one user: 4 of 5 would disappear
        small = Snapshot(users={"u1": User("u1", "alice")}, groups={"g1": Group("g1", "support")}, memberships={"u1": {"g1"}})
        e = self.raises("removal_guard", directory.sync, small, self.path)
        self.assertEqual(e.detail["removal_fraction"], 0.8)
        self.assertEqual(self.path.read_text(encoding="utf-8"), self.original)
        # the users are all there but every group came back empty
        empty = snapshot({"g1": [], "g2": [], "g3": []})
        e = self.raises("removal_guard", directory.sync, empty, self.path, group_map=GROUP_MAP)
        self.assertGreater(e.detail["lost_membership_fraction"], 0.3)
        self.assertEqual(self.path.read_text(encoding="utf-8"), self.original)
        self.assertEqual(sorted(os.listdir(self.bundle)), sorted(os.listdir(BUNDLE)))
        r = directory.sync(small, self.path, force=True)
        self.assertTrue(r["written"])
        self.assertTrue(json.loads((self.bundle / "entities.sync.json").read_text())["forced"])
        self.assertTrue(directory.sync(snapshot(), self.path, max_removal_fraction=0.0)["written"])  # adding is never guarded

    def test_atomic_write_on_failure(self):
        listing = sorted(os.listdir(self.bundle))
        dup = json.loads(self.original) + [{"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []}]
        self.raises("entities_invalid", directory.write_entities, self.path, dup, source="test")
        bad = [{"uid": {"type": "User", "id": "zed"}, "attrs": {}, "parents": [{"type": "bad type", "id": 1}]}]
        self.raises("entities_invalid", directory.write_entities, self.path, bad, source="test", force=True)
        good = directory.to_entities(snapshot(), json.loads(self.original), group_map=GROUP_MAP)
        with mock.patch("os.replace", side_effect=OSError(28, "No space left on device")):
            self.raises("write_failed", directory.write_entities, self.path, good, source="test")
        self.assertEqual(self.path.read_text(encoding="utf-8"), self.original)
        self.assertEqual(sorted(os.listdir(self.bundle)), listing, "no temporary file may be left behind")
        self.path.write_text("{not json", encoding="utf-8")
        self.raises("entities_unreadable", directory.write_entities, self.path, good, source="test")
        self.assertEqual(self.path.read_text(encoding="utf-8"), "{not json")

    def test_diff(self):
        old = json.loads(self.original)
        new = directory.to_entities(snapshot(), old)
        d = directory.diff(old, new)
        self.assertEqual((d["users_added"], d["users_removed"]), ([], ["dave"]))
        self.assertEqual([c["user"] for c in d["membership_changed"]], ["carol"])
        self.assertEqual(d["membership_changed"][0], {"user": "carol", "added": ["Group::emea", "Group::support"], "removed": ["Group::compliance"]})


# ---- cloud generators: an independent evaluator ----------------------------------------

def iam_match(pattern, s):
    """IAM wildcard matching: * any run of characters, ? any one character."""
    return re.fullmatch("".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern), s, re.S) is not None


def policy_allows(policy, action, arn):
    hit = lambda st: any(iam_match(a.lower(), action.lower()) for a in as_list(st["Action"])) and any(iam_match(r, arn) for r in as_list(st["Resource"]))
    if any(st["Effect"] == "Deny" and hit(st) for st in policy["Statement"]):
        return False
    return any(st["Effect"] == "Allow" and hit(st) for st in policy["Statement"])


def as_list(v):
    return v if isinstance(v, list) else [v]


def boundary_allows(boundary, bucket, role, obj):
    for r in boundary["accessBoundary"]["accessBoundaryRules"]:
        if r["availableResource"] != f"//storage.googleapis.com/projects/_/buckets/{bucket}" or "inRole:" + role not in r["availablePermissions"]:
            continue
        expr = r.get("availabilityCondition", {}).get("expression")
        name = f"projects/_/buckets/{bucket}/objects/{obj}"
        if expr is None:
            return True
        m = re.fullmatch(r"resource\.name\.startsWith\('([^']*)'\)", expr)
        if m and name.startswith(m.group(1)):
            return True
        m = re.fullmatch(r"resource\.name == '([^']*)'", expr)
        if m and name == m.group(1):
            return True
        if not re.fullmatch(r"resource\.name(\.startsWith\('[^']*'\)| == '[^']*')", expr):
            raise AssertionError(f"the test evaluator does not understand: {expr}")
    return False


ACTIONS = ["read", "update", "delete", "list", "remove", "readx"]
PATHS = ["s3.object", "s3.report", "hr.file"]
SEGS = ["a", "b", "reports", "x1", "a?c", "abc", "2024"]


def rand_id(rng, depth=3):
    return "/".join(rng.choice(SEGS) for _ in range(rng.randint(1, depth)))


def rand_pattern(rng):
    k = rng.random()
    if k < 0.08:
        return "*"
    if k < 0.16:
        return rng.choice(["s3.*", "s3.obj*", "hr*"])
    path, i = rng.choice(PATHS), rand_id(rng)
    if k < 0.55:
        return f"{path}/{i}"[:rng.randint(len(path) + 1, len(path) + 1 + len(i))] + "*"
    if k < 0.7:
        return f"{path}/*"
    return f"{path}/{i}"


def rand_action(rng):
    return rng.choice(ACTIONS[:4] + ["*", "re*", "read"])


def rand_cap(rng):
    return {"actions": sorted({rand_action(rng) for _ in range(rng.randint(1, 3))}),
            "resources": sorted({rand_pattern(rng) for _ in range(rng.randint(1, 3))})}


def rand_rule_base(rng):
    while True:
        r = rand_pattern(rng)
        if "/" in r:
            return {"action": rand_action(rng), "resource": r}


def concrete_resources(rng, patterns):
    out = set()
    for p in patterns:
        stem = p[:-1] if p.endswith("*") else p
        out.update({stem, stem + "z", stem + "/z", stem + rand_id(rng), stem[:-1]})
    for _ in range(25):
        out.add(f"{rng.choice(PATHS)}/{rand_id(rng)}")
    return sorted(r for r in out if "/" in r and not r.endswith("/") and "*" not in r)


class Generators(Tmp):
    """For seeded random capabilities and maps, what is generated never
    grants an (action, resource) the capability does not allow."""
    ROUNDS = 300

    def cases(self, cloud, make_rule):
        rng = random.Random(20240601 + len(cloud))
        for n in range(self.ROUNDS):
            rule_list = [{**rand_rule_base(rng), **make_rule(rng, i)} for i in range(rng.randint(1, 5))]
            cap = rand_cap(rng)
            resources = concrete_resources(rng, cap["resources"] + [r["resource"] for r in rule_list])
            yield n, cap, rule_list, tokens.Cap.from_json(cap), resources

    def test_aws_policy_is_never_wider_than_the_cap(self):
        def make(rng, i):
            res = [f"arn:aws:s3:::bkt{i}/{{id}}"] + ([f"arn:aws:s3:::bkt{i}"] if rng.random() < 0.4 else [])
            return {"allow": {"Action": [f"svc{i}:Act{i}"], "Resource": res}}
        allowed = denied = 0
        for n, cap, rule_list, c, resources in self.cases("aws", make):
            policy = aws.session_policy(cap, {"aws": {"rules": rule_list}})
            self.assertEqual(policy, aws.session_policy(cap, {"aws": {"rules": rule_list}}))
            self.assertLessEqual(len(aws.policy_json(policy)), 2048)
            for i, rule in enumerate(rule_list):
                for a in ACTIONS:
                    for res in resources:
                        if not (tokens.matches(rule["action"], a) and tokens.matches(rule["resource"], res)):
                            continue
                        path, rid = res.split("/", 1)
                        for template in rule["allow"]["Resource"]:
                            if policy_allows(policy, f"svc{i}:Act{i}", template.replace("{id}", rid)):
                                allowed += 1
                                self.assertTrue(c.allows_action(a) and c.allows_resource(path, rid),
                                                f"round {n}: cap {cap} does not allow ({a}, {res}) but the policy grants {template} via rule {rule}: {policy}")
                            else:
                                denied += 1
        self.assertGreater(allowed, 500, "the property test must not be vacuous")
        self.assertGreater(denied, 500)

    def test_gcp_boundary_is_never_wider_than_the_cap(self):
        def make(rng, i):
            k = rng.random()
            extra = {} if k < 0.25 else {"prefix": "{id}"} if k < 0.7 else {"prefix": "exports/{id}"} if k < 0.9 else {"prefix": "fixed/"}
            return {"bucket": f"bucket-{i}", "role": f"roles/custom.r{i}", **extra}
        allowed = 0
        for n, cap, rule_list, c, resources in self.cases("gcp", make):
            try:
                boundary = gcp.access_boundary(cap, {"gcp": {"rules": rule_list}})
            except BridgeError as e:
                self.assertIn(e.code, ("empty_boundary", "boundary_too_large"))
                continue
            self.assertLessEqual(len(boundary["accessBoundary"]["accessBoundaryRules"]), 10)
            for i, rule in enumerate(rule_list):
                for a in ACTIONS:
                    for res in resources:
                        if not (tokens.matches(rule["action"], a) and tokens.matches(rule["resource"], res)):
                            continue
                        path, rid = res.split("/", 1)
                        obj = rule["prefix"].replace("{id}", rid) if "{id}" in rule.get("prefix", "") else rule.get("prefix", "") + rid
                        if boundary_allows(boundary, f"bucket-{i}", f"roles/custom.r{i}", obj):
                            allowed += 1
                            self.assertTrue(c.allows_action(a) and c.allows_resource(path, rid),
                                            f"round {n}: cap {cap} does not allow ({a}, {res}) but the boundary grants it via {rule}: {boundary}")
        self.assertGreater(allowed, 500)

    def test_azure_scopes_are_never_wider_than_the_cap(self):
        make = lambda rng, i: {"scopes": [f"https://api{i % 2}.example/Scope{i}"]}
        granted = 0
        for n, cap, rule_list, c, resources in self.cases("azure", make):
            got = azure.scopes(cap, {"azure": {"rules": rule_list}})
            flat = {s for v in got["by_resource"].values() for s in v}
            for i, rule in enumerate(rule_list):
                if f"https://api{i % 2}.example/Scope{i}" not in flat:
                    continue
                for a in ACTIONS:
                    for res in resources:
                        if tokens.matches(rule["action"], a) and tokens.matches(rule["resource"], res):
                            granted += 1
                            path, rid = res.split("/", 1)
                            self.assertTrue(c.allows_action(a) and c.allows_resource(path, rid), f"round {n}: {cap} vs {rule}")
        self.assertGreater(granted, 500)


MAP = json.loads((ROOT / "examples" / "bridges" / "cloud_map.json").read_text(encoding="utf-8"))


class Aws(Tmp):
    CAP = {"actions": ["read"], "resources": ["s3.object/reports/*"], "deny_labels": ["secret"], "budget": {"EUR": 5}}

    def test_session_policy(self):
        report = aws.session_policy_report(self.CAP, MAP)
        self.assertEqual(report["policy"], {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::crm-exports/reports/*"]}]})
        self.assertEqual(report["not_enforced"], {"deny_labels": ["secret"], "budget": {"EUR": 5}})
        self.assertIn({"action": "list", "resource": "s3.object/reports/*", "reason": "cannot_narrow", "template": "arn:aws:s3:::crm-exports"},
                      aws.session_policy_report({"actions": ["*"], "resources": ["s3.object/reports/*"]}, MAP)["skipped"])
        whole = aws.session_policy({"actions": ["*"], "resources": ["*"]}, MAP)
        self.assertTrue(policy_allows(whole, "s3:ListBucket", "arn:aws:s3:::crm-exports"))
        self.assertTrue(policy_allows(whole, "s3:PutObject", "arn:aws:s3:::crm-exports/x"))
        one = aws.session_policy({"actions": ["read"], "resources": ["s3.object/reports/q1.csv"]}, MAP)
        self.assertEqual(one["Statement"][0]["Resource"], ["arn:aws:s3:::crm-exports/reports/q1.csv"])

    def test_unmapped_is_default_deny(self):
        report = aws.session_policy_report({"actions": ["read"], "resources": ["crm.customer/*"]}, MAP)
        self.assertEqual(report["policy"]["Statement"], [{"Effect": "Deny", "Action": "*", "Resource": "*"}])
        self.assertEqual(report["skipped"], [{"action": "read", "resource": "crm.customer/*", "reason": "unmapped"}])
        self.assertFalse(policy_allows(report["policy"], "s3:GetObject", "arn:aws:s3:::crm-exports/x"))
        self.assertEqual(aws.session_policy({"actions": [], "resources": []}, MAP)["Statement"][0]["Effect"], "Deny")
        self.assertEqual(aws.session_policy(self.CAP, {})["Statement"][0]["Effect"], "Deny")

    def test_ids_with_iam_wildcards_are_not_granted(self):
        for rid in ("a?c", "${aws:username}/x", "a?c/*"):
            report = aws.session_policy_report({"actions": ["read"], "resources": [f"s3.object/{rid}"]}, MAP)
            self.assertEqual(report["policy"]["Statement"][0]["Effect"], "Deny", rid)
            self.assertEqual(report["skipped"][0]["reason"], "unsafe_id")

    def test_policy_size_limit(self):
        big = {"actions": ["read"], "resources": [f"s3.object/customer-{i:04d}/exports/*" for i in range(60)]}
        e = self.raises("policy_too_large", aws.session_policy, big, MAP)
        self.assertGreater(e.detail["size"], 2048)
        ok = {"actions": ["read"], "resources": [f"s3.object/customer-{i:04d}/exports/*" for i in range(20)]}
        self.assertLessEqual(len(aws.policy_json(aws.session_policy(ok, MAP))), 2048)

    def test_bad_map_is_refused(self):
        for bad in ({"aws": {"rules": [{"action": "read", "resource": "s3.object/*", "alow": {}}]}},
                    {"aws": {"rules": [{"action": "read", "resource": "s3.object", "allow": {"Action": ["a"], "Resource": ["b"]}}]}},
                    {"aws": {"rules": [{"action": "r*d", "resource": "s3.object/*", "allow": {"Action": ["a"], "Resource": ["b"]}}]}},
                    {"aws": {"rules": [{"action": "read", "resource": "s3.object/*", "allow": {"Action": "a", "Resource": ["b"]}}]}},
                    {"aws": {"rules": [{"action": "read", "resource": "s3.object/*", "allow": {"Action": ["a"], "Resource": ["b"]}, "resorce": "x/*"}]}},
                    {"aws": {"rules": [{"action": "read", "resource": "s3.object/*", "allow": {"Action": ["a"], "Resource": ["b"], "NotResource": ["c"]}}]}},
                    {"awss": {"rules": []}}, {"gcp": {"rules": [{"action": "read", "resource": "g/*", "bucket": "b", "role": "r", "prefix": "{id}/x"}]}},
                    {"azure": {"rules": [{"action": "read", "resource": "g/*"}]}},
                    {"azure": {"rules": [{"action": "read", "resource": "g/*", "data_actions": ["x/read"]}]}}):
            self.raises("map_invalid", aws.session_policy, self.CAP, bad)
        self.raises("invalid_cap", aws.session_policy, {"actions": ["r*d"], "resources": ["x/*"]}, MAP)
        self.raises("invalid_cap", aws.session_policy, {"actions": ["read"], "resource": ["x/*"]}, MAP)

    def grant(self, **kw):
        e = Engine(conformance_config(os.path.join(self.dir, "state")))
        self.addCleanup(e.close)
        return e, core.delegate(e, user="alice", agent="support-bot", task="ticket 7/é", now=1700000000,
                                capability={"actions": ["read"], "resources": ["s3.object/reports/*"]}, **kw)

    def test_assume_role_request(self):
        e, g = self.grant(ttl=600)
        arn = "arn:aws:iam::123456789012:role/support"
        claims_ = e.keys.verify(g.token, e.issuer)
        req = aws.assume_role_request(claims_, None, MAP, arn, now=1700000000)
        self.assertEqual(set(req), {"RoleArn", "RoleSessionName", "Policy", "DurationSeconds", "Tags", "TransitiveTagKeys"})
        self.assertEqual(req["RoleArn"], arn)
        self.assertRegex(req["RoleSessionName"], r"^[A-Za-z0-9_+=,.@-]{2,64}$")
        self.assertEqual(req["RoleSessionName"], f"support-bot-{g.token_id}")
        self.assertEqual(json.loads(req["Policy"]), aws.session_policy(g.capability, MAP))
        self.assertEqual(req["DurationSeconds"], 900)     # 600 seconds left, AWS's minimum is 900
        tags = {t["Key"]: t["Value"] for t in req["Tags"]}
        self.assertEqual(tags, {"sd_user": "alice", "sd_agent": "support-bot", "sd_task": "ticket 7/-", "sd_token_id": g.token_id})
        self.assertEqual(req["TransitiveTagKeys"], list(tags))
        self.assertEqual(aws.assume_role_request(g, None, MAP, arn, now=1700000000), req)    # the Grant carries the task too
        issued = e.issue_token("support-bot", {"actions": ["read"], "resources": ["s3.object/reports/*"]}, user="alice", task="ticket-9")
        self.assertIn({"Key": "sd_task", "Value": "ticket-9"}, aws.assume_role_request(issued, None, MAP, arn)["Tags"])
        self.assertEqual(aws.duration_for(1700000600, 1700000000), (900, 300))
        self.assertEqual(aws.duration_for(1700003000, 1700000000, 3600), (3000, 0))
        self.assertEqual(aws.duration_for(1700090000, 1700000000, 3600), (3600, 0))
        self.raises("token_expired", aws.assume_role_request, g, None, MAP, arn, now=1700000600)
        self.raises("invalid_input", aws.assume_role_request, g, None, MAP, "arn:aws:s3:::bucket", now=1700000000)
        self.raises("invalid_input", aws.assume_role_request, {"sub": "user:alice"}, None, MAP, arn)
        narrower = aws.assume_role_request(g, {"actions": ["read"], "resources": ["s3.object/reports/2024/*"]}, MAP, arn, now=1700000000)
        self.assertIn("crm-exports/reports/2024/*", narrower["Policy"])
        self.raises("widening", aws.assume_role_request, g, {"actions": ["read"], "resources": ["s3.object/*"]}, MAP, arn, now=1700000000)

    def test_role_tag_and_binding_from_roles_json(self):
        e = Engine(conformance_config(os.path.join(self.dir, "state")))
        self.addCleanup(e.close)
        role = {r.name: r for r in core.roles(e)}["break-glass"]
        g = core.delegate(e, user="carol", agent="support-bot", role="break-glass", task="incident-1")
        req = aws.assume_role_request(g, None, {"aws": {"rules": [{"action": "read", "resource": "hr.salary/*", "allow": {
            "Action": ["dynamodb:GetItem"], "Resource": ["arn:aws:dynamodb:eu-west-1:123456789012:table/salary"]}}]}}, role.bindings["aws"]["role_arn"])
        self.assertEqual(req["RoleArn"], "arn:aws:iam::123456789012:role/hr-break-glass")
        self.assertIn({"Key": "sd_role", "Value": "break-glass"}, req["Tags"])
        self.assertLessEqual(req["DurationSeconds"], 900)

    def test_assume_role_with_a_fake_client(self):
        class Sts:
            def __init__(self, answer=None, error=None):
                self.answer, self.error, self.seen = answer, error, None

            def assume_role(self, **kw):
                self.seen = kw
                if self.error:
                    raise self.error
                return self.answer
        _, g = self.grant()
        req = aws.assume_role_request(g, None, MAP, "arn:aws:iam::123456789012:role/support", now=1700000000)
        creds = {"AccessKeyId": "ASIA", "SecretAccessKey": "s", "SessionToken": "t", "Expiration": "x"}
        sts = Sts({"Credentials": creds})
        self.assertEqual(aws.assume_role(req, sts), creds)
        self.assertEqual(sts.seen, req)
        self.raises("aws_error", aws.assume_role, req, Sts(error=RuntimeError("AccessDenied " + fakes.TOKEN)))
        self.raises("malformed_response", aws.assume_role, req, Sts({"Credentials": {}}))
        self.raises("invalid_input", aws.assume_role, {k: v for k, v in req.items() if k != "Policy"}, sts)

    def results(self, deny=()):
        req = aws.simulation_request(MAP, "arn:aws:iam::123456789012:user/alice")
        return req, [{"EvalActionName": a, "EvalResourceName": r, "EvalDecision": "implicitDeny" if (a, r) in deny else "allowed"}
                     for a in req["ActionNames"] for r in req["ResourceArns"]]

    def test_ceiling_from_simulation(self):
        req, results = self.results()
        self.assertEqual(req, {"PolicySourceArn": "arn:aws:iam::123456789012:user/alice", "ActionNames": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                               "ResourceArns": ["arn:aws:s3:::crm-exports", "arn:aws:s3:::crm-exports/*"]})
        self.assertEqual(aws.ceiling_from_simulation(results, MAP), {"actions": ["list", "read", "update"], "resources": ["s3.object/*"]})
        self.assertEqual(aws.ceiling_from_simulation({"EvaluationResults": results, "IsTruncated": False}, MAP)["actions"], ["list", "read", "update"])
        # update needs PutObject AND GetObject: one of the two denied keeps update out
        _, results = self.results(deny={("s3:PutObject", "arn:aws:s3:::crm-exports/*")})
        self.assertEqual(aws.ceiling_from_simulation(results, MAP), {"actions": ["list", "read"], "resources": ["s3.object/*"]})
        _, results = self.results(deny={("s3:GetObject", "arn:aws:s3:::crm-exports/*")})
        self.assertEqual(aws.ceiling_from_simulation(results, MAP), {"actions": ["list"], "resources": ["s3.object/*"]})
        self.assertEqual(aws.ceiling_from_simulation([], MAP), {"actions": [], "resources": []})          # no result is not "allowed"
        _, results = self.results()
        self.assertEqual(aws.ceiling_from_simulation(results[:-1] + [dict(results[-1], EvalDecision="explicitDeny")], MAP)["actions"], ["list", "read"])
        self.raises("truncated_pagination", aws.ceiling_from_simulation, {"EvaluationResults": results, "IsTruncated": True, "Marker": "m"}, MAP)
        self.raises("malformed_response", aws.ceiling_from_simulation, [{"EvalActionName": "s3:GetObject"}], MAP)
        wild = {"aws": {"rules": [{"action": "read", "resource": "s3.object/*", "allow": {"Action": ["s3:Get*"], "Resource": ["*"]}}]}}
        self.raises("nothing_to_simulate", aws.simulation_request, wild, "arn:aws:iam::123456789012:user/alice")
        self.assertEqual(aws.ceiling_from_simulation(results, wild), {"actions": [], "resources": []})


class Gcp(Tmp):
    def test_access_boundary(self):
        b = gcp.access_boundary({"actions": ["read"], "resources": ["gcs.object/reports/*"]}, MAP)
        self.assertEqual(b, {"accessBoundary": {"accessBoundaryRules": [{
            "availableResource": "//storage.googleapis.com/projects/_/buckets/crm-exports",
            "availablePermissions": ["inRole:roles/storage.objectViewer"],
            "availabilityCondition": {"expression": "resource.name.startsWith('projects/_/buckets/crm-exports/objects/reports/')"}}]}})
        one = gcp.access_boundary({"actions": ["read"], "resources": ["gcs.object/reports/q1.csv"]}, MAP)
        self.assertEqual(one["accessBoundary"]["accessBoundaryRules"][0]["availabilityCondition"]["expression"],
                         "resource.name == 'projects/_/buckets/crm-exports/objects/reports/q1.csv'")
        whole = gcp.access_boundary({"actions": ["*"], "resources": ["gcs.object/*"]}, MAP)["accessBoundary"]["accessBoundaryRules"]
        self.assertEqual(whole, [{"availableResource": "//storage.googleapis.com/projects/_/buckets/crm-exports",
                                  "availablePermissions": ["inRole:roles/storage.objectCreator", "inRole:roles/storage.objectViewer"]}])
        self.raises("empty_boundary", gcp.access_boundary, {"actions": ["read"], "resources": ["crm.customer/*"]}, MAP)
        report = gcp.access_boundary_report({"actions": ["read"], "resources": ["gcs.object/it's", "gcs.object/ok"], "deny_fields": ["x"]}, MAP)
        self.assertEqual(report["skipped"], [{"action": "read", "resource": "gcs.object/it's", "reason": "unsafe_id"}])
        self.assertEqual(report["not_enforced"], {"deny_fields": ["x"]})
        lp = {"gcp": {"rules": [{"action": "read", "resource": "g.o/*", "bucket": "bkt", "role": "roles/storage.objectViewer", "prefix": "{id}", "list_prefix": True}]}}
        expr = gcp.access_boundary({"actions": ["read"], "resources": ["g.o/a/*"]}, lp)["accessBoundary"]["accessBoundaryRules"][0]["availabilityCondition"]["expression"]
        self.assertEqual(expr, "resource.name.startsWith('projects/_/buckets/bkt/objects/a/') || "
                               "api.getAttribute('storage.googleapis.com/objectListPrefix', '').startsWith('a/')")

    def test_rule_limit(self):
        many = {"gcp": {"rules": [{"action": "read", "resource": f"gcs.b{i}/*", "bucket": f"bucket-{i}", "role": "roles/storage.objectViewer"} for i in range(11)]}}
        e = self.raises("boundary_too_large", gcp.access_boundary, {"actions": ["read"], "resources": ["*"]}, many)
        self.assertEqual(e.detail, {"rules": 11})
        many["gcp"]["rules"].pop()
        self.assertEqual(len(gcp.access_boundary({"actions": ["read"], "resources": ["*"]}, many)["accessBoundary"]["accessBoundaryRules"]), 10)

    def test_sts_exchange_request(self):
        b = gcp.access_boundary({"actions": ["read"], "resources": ["gcs.object/reports/*"]}, MAP)
        req = gcp.sts_exchange_request(b, "ya29.source")
        self.assertEqual((req["method"], req["url"]), ("POST", "https://sts.googleapis.com/v1/token"))
        self.assertEqual(req["form"]["grant_type"], "urn:ietf:params:oauth:grant-type:token-exchange")
        self.assertEqual(req["form"]["subject_token_type"], "urn:ietf:params:oauth:token-type:access_token")
        self.assertEqual(req["form"]["requested_token_type"], "urn:ietf:params:oauth:token-type:access_token")
        self.assertEqual(req["form"]["subject_token"], "ya29.source")
        self.assertEqual(json.loads(req["form"]["options"]), b)
        self.raises("invalid_input", gcp.sts_exchange_request, {"accessBoundary": {"accessBoundaryRules": []}}, "ya29.source")
        self.raises("no_credential", gcp.sts_exchange_request, b, "")
        seen = {}

        def sts(method, url, headers, body):
            seen.update(method=method, url=url, body=body.decode())
            return fakes.js(200, {"access_token": "ya29.downscoped", "token_type": "Bearer", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"})
        self.assertEqual(gcp.exchange(req, sts)["access_token"], "ya29.downscoped")
        self.assertIn("options=%7B%22accessBoundary%22", seen["body"])
        with self.assertRaises(BridgeError) as cm:
            gcp.exchange(req, lambda *a: fakes.js(400, {"error": "invalid_grant", "error_description": "ya29.source"}))
        self.assertNotIn("ya29.source", str(cm.exception))
        self.raises("malformed_response", gcp.exchange, req, lambda *a: fakes.js(200, {}))

    def test_ceiling_from_test_permissions(self):
        reqs = gcp.test_permissions_requests(MAP)
        self.assertEqual(reqs, [{"method": "GET", "bucket": "crm-exports", "permissions": ["storage.objects.create", "storage.objects.get"],
                                 "url": "https://storage.googleapis.com/storage/v1/b/crm-exports/iam/testPermissions"
                                        "?permissions=storage.objects.create&permissions=storage.objects.get"}])
        both = [{"kind": "storage#testIamPermissionsResponse", "permissions": ["storage.objects.get", "storage.objects.create"]}]
        self.assertEqual(gcp.ceiling_from_test_permissions(both, MAP), {"actions": ["read", "update"], "resources": ["gcs.object/*"]})
        self.assertEqual(gcp.ceiling_from_test_permissions([{"permissions": ["storage.objects.get"]}], MAP), {"actions": ["read"], "resources": ["gcs.object/*"]})
        self.assertEqual(gcp.ceiling_from_test_permissions([{"kind": "storage#testIamPermissionsResponse"}], MAP), {"actions": [], "resources": []})
        self.raises("invalid_input", gcp.ceiling_from_test_permissions, [], MAP)
        self.raises("malformed_response", gcp.ceiling_from_test_permissions, [{"permissions": "storage.objects.get"}], MAP)


class Azure(Tmp):
    BLOB = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/"

    def test_scopes_and_obo_request(self):
        cap = {"actions": ["read"], "resources": ["graph.mail/*"]}
        self.assertEqual(azure.scopes(cap, MAP)["by_resource"], {"https://graph.microsoft.com": ["https://graph.microsoft.com/Mail.Read"]})
        req = azure.obo_request(cap, MAP, tenant="contoso.onmicrosoft.com", client_id="client-1", user_assertion="eyJ.user.token")
        self.assertEqual(req["url"], "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token")
        self.assertEqual(req["form"], {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "client_id": "client-1",
                                       "assertion": "eyJ.user.token", "scope": "https://graph.microsoft.com/Mail.Read",
                                       "requested_token_use": "on_behalf_of"})
        self.assertNotIn("client_secret", req["form"])
        # a cap narrower than the rule cannot be expressed as a scope: nothing is requested
        narrow = azure.scopes({"actions": ["read"], "resources": ["graph.mail/inbox-1"]}, MAP)
        self.assertEqual(narrow["by_resource"], {})
        self.assertEqual(narrow["skipped"], [{"action": "read", "resource": "graph.mail/inbox-1", "reason": "cannot_narrow"}])
        self.raises("no_scopes", azure.obo_request, {"actions": ["read"], "resources": ["graph.mail/inbox-1"]}, MAP, tenant="t", client_id="c", user_assertion="a")
        self.raises("no_credential", azure.obo_request, cap, MAP, tenant="t", client_id="c", user_assertion="")

    def test_one_resource_per_request(self):
        cap = {"actions": ["read", "create"], "resources": ["graph.mail/*", "crm.api/*"]}
        e = self.raises("multiple_resources", azure.obo_request, cap, MAP, tenant="t", client_id="c", user_assertion="a")
        self.assertEqual(e.detail, {"api://crm-api": ["api://crm-api/Customers.Read"],
                                    "https://graph.microsoft.com": ["https://graph.microsoft.com/Mail.Read", "https://graph.microsoft.com/Mail.Send"]})
        req = azure.obo_request(cap, MAP, tenant="t", client_id="c", user_assertion="a", resource="https://graph.microsoft.com")
        self.assertEqual(req["form"]["scope"], "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.Send")
        self.raises("no_scopes", azure.obo_request, cap, MAP, tenant="t", client_id="c", user_assertion="a", resource="https://vault.azure.net")

    def test_rbac_matching(self):
        reader = {"actions": ["*/read"], "notActions": [], "dataActions": [], "notDataActions": []}
        contributor = {"actions": ["*"], "notActions": ["Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write"], "dataActions": [], "notDataActions": []}
        self.assertTrue(azure.rbac_allows([reader], "Microsoft.Compute/virtualMachines/read"))
        self.assertFalse(azure.rbac_allows([reader], "Microsoft.Compute/virtualMachines/write"))
        self.assertTrue(azure.rbac_allows([contributor], "Microsoft.Compute/virtualMachines/write"))
        self.assertFalse(azure.rbac_allows([contributor], "Microsoft.Authorization/roleAssignments/write"))   # NotActions, case-insensitive
        owner = {"actions": ["*"], "notActions": []}
        self.assertTrue(azure.rbac_allows([contributor, owner], "Microsoft.Authorization/roleAssignments/write"))  # NotActions is not a deny
        self.assertFalse(azure.rbac_allows([contributor], self.BLOB + "read", data=True))                      # control plane is not data plane
        data = {"actions": [], "dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"], "notDataActions": [self.BLOB + "delete"]}
        self.assertTrue(azure.rbac_allows([data], self.BLOB + "read", data=True))
        self.assertFalse(azure.rbac_allows([data], self.BLOB + "delete", data=True))
        self.assertFalse(azure.rbac_allows([], self.BLOB + "read", data=True))

    def test_ceiling_from_permissions(self):
        scope = MAP["azure"]["rules"][3]["scope"]
        self.assertEqual(azure.permissions_request(scope)["url"], "https://management.azure.com" + scope +
                         "/providers/Microsoft.Authorization/permissions?api-version=2022-04-01")
        self.raises("invalid_input", azure.permissions_request, "https://evil.example/x")
        reader = [{"actions": ["*/read"], "notActions": [], "dataActions": [self.BLOB + "read"], "notDataActions": []}]
        self.assertEqual(azure.ceiling_from_permissions(reader, MAP), {"actions": ["read"], "resources": ["blob.object/*"]})
        self.assertEqual(azure.ceiling_from_permissions({"value": reader}, MAP), {"actions": ["read"], "resources": ["blob.object/*"]})
        self.assertEqual(azure.ceiling_from_permissions({scope: reader}, MAP), {"actions": ["read"], "resources": ["blob.object/*"]})
        writer = [{"actions": [], "notActions": [], "dataActions": [self.BLOB + "*"], "notDataActions": []}]
        self.assertEqual(azure.ceiling_from_permissions(writer, MAP), {"actions": ["read", "update"], "resources": ["blob.object/*"]})
        no_write = [{"actions": [], "notActions": [], "dataActions": [self.BLOB + "*"], "notDataActions": [self.BLOB + "write"]}]
        self.assertEqual(azure.ceiling_from_permissions(no_write, MAP), {"actions": ["read"], "resources": ["blob.object/*"]})
        self.assertEqual(azure.ceiling_from_permissions([], MAP), {"actions": [], "resources": []})
        self.raises("truncated_pagination", azure.ceiling_from_permissions, {"value": reader, "nextLink": "https://management.azure.com/next"}, MAP)
        self.raises("malformed_response", azure.ceiling_from_permissions, [{"dataActions": "x"}], MAP)


# ---- ceilings ------------------------------------------------------------------------

class Ceiling(Tmp):
    def test_pairs_to_cap_is_a_product_inside_the_pairs(self):
        rng = random.Random(7)
        for _ in range(300):
            pairs = sorted({(rng.choice("abcd"), rng.choice("wxyz") + "/*") for _ in range(rng.randint(0, 9))})
            d = cloudmap.pairs_to_cap(pairs)
            got = {(a, r) for a in d["cap"]["actions"] for r in d["cap"]["resources"]}
            self.assertTrue(got <= set(pairs))
            self.assertEqual(got | {tuple(p) for p in d["dropped"]}, set(pairs))
            self.assertEqual(bool(got), bool(pairs))
        d = cloudmap.pairs_to_cap([("read", "a/*"), ("update", "b/*")])
        self.assertEqual((len(d["cap"]["actions"]), len(d["cap"]["resources"]), len(d["dropped"])), (1, 1, 1))

    def test_overlapping_rules_must_all_be_allowed(self):
        rule_list = [{"action": "*", "resource": "s/*"}, {"action": "read", "resource": "s/secret/*"}, {"action": "read", "resource": "t/*"}]
        self.assertEqual(cloudmap.allowed_pairs(rule_list, [True, False, True]), [("read", "t/*")])
        self.assertEqual(cloudmap.allowed_pairs(rule_list, [True, True, False]), [("*", "s/*"), ("read", "s/secret/*")])
        twice = [{"action": "read", "resource": "s/*"}, {"action": "read", "resource": "s/*"}]
        self.assertEqual(cloudmap.allowed_pairs(twice, [True, False]), [])

    def test_intersect_examples(self):
        role = {"actions": ["read", "create", "update"], "resources": ["crm.customer/*", "billing.refund/*"], "deny_labels": ["secret"], "budget": {"EUR": 10000}}
        human = {"actions": ["re*", "delete"], "resources": ["crm.customer/eu-*", "hr.salary/*"], "deny_labels": ["pii"], "budget": {"EUR": 500, "USD": 9}}
        self.assertEqual(ceiling.intersect(role, human), {"actions": ["read"], "resources": ["crm.customer/eu-*"], "deny_labels": ["pii", "secret"],
                                                          "deny_fields": [], "budget": {"EUR": 500}})
        self.assertEqual(ceiling.intersect(role, {"actions": ["*"], "resources": ["*"]})["budget"], {})
        nothing = ceiling.intersect(role, {"actions": ["delete"], "resources": ["*"]})
        self.assertEqual((nothing["actions"], nothing["resources"]), ([], ["billing.refund/*", "crm.customer/*"]))
        self.assertFalse(tokens.Cap.from_json(nothing).allows_action("read"))

    def test_intersect_properties(self):
        rng = random.Random(42)
        labels = ["pii", "secret", "financial"]

        def cap():
            c = rand_cap(rng)
            c["deny_labels"] = sorted(set(rng.sample(labels, rng.randint(0, 2))))
            c["budget"] = {k: rng.randint(0, 100) for k in rng.sample(["EUR", "USD"], rng.randint(0, 2))}
            return c
        samples_a = ACTIONS + ["x"]
        for n in range(400):
            a, b = cap(), cap()
            i = ceiling.intersect(a, b)
            ci, ca, cb = (tokens.Cap.from_json(x) for x in (i, a, b))
            ci.validate()
            ci.check_narrower_than(ca)       # narrower than both, by the engine's own rule
            ci.check_narrower_than(cb)
            self.assertEqual(ceiling.intersect(i, i), i)                   # idempotent
            self.assertEqual(ceiling.intersect(i, b), i)
            self.assertEqual(ceiling.intersect(i, a), i)
            self.assertEqual(i, ceiling.intersect(b, a))                   # symmetric
            for res in concrete_resources(rng, a["resources"] + b["resources"]):   # and exactly the intersection on samples
                path, rid = res.split("/", 1)
                self.assertEqual(ci.allows_resource(path, rid), ca.allows_resource(path, rid) and cb.allows_resource(path, rid), (n, a, b, i, res))
            for act in samples_a:
                self.assertEqual(ci.allows_action(act), ca.allows_action(act) and cb.allows_action(act), (n, a, b, i, act))

    def roles(self):
        path = Path(self.dir) / "roles.json"
        shutil.copy(BUNDLE / "roles.json", path)
        return path

    def test_cap_role_never_widens(self):
        path = self.roles()
        before_text = path.read_text(encoding="utf-8")
        human = {"actions": ["read", "delete"], "resources": ["crm.customer/*", "hr.salary/*"]}
        r = ceiling.cap_role(path, "support-agent", human)
        self.assertEqual((r["changed"], r["written"]), (True, False))
        self.assertEqual(path.read_text(encoding="utf-8"), before_text)
        self.assertEqual(r["after"], {"actions": ["read"], "resources": ["crm.customer/*"], "deny_labels": ["secret"], "budget": {"EUR": 10000}})
        r = ceiling.cap_role(path, "support-agent", human, write=True)
        self.assertTrue(r["written"])
        doc = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(doc["roles"]["support-agent"]["cap"], r["after"])
        self.assertEqual(doc["roles"]["support-agent"]["max_ttl"], 600)
        self.assertEqual(doc["roles"]["supervisor"], json.loads(before_text)["roles"]["supervisor"])
        # a "wider" human cap changes nothing, and a second run is a no-op
        r = ceiling.cap_role(path, "support-agent", {"actions": ["*"], "resources": ["*"]}, write=True)
        self.assertEqual((r["changed"], r["written"]), (False, False))
        self.assertEqual(ceiling.cap_role(path, "support-agent", human, write=True)["changed"], False)
        self.assertEqual(ceiling.cap_role(path, "support-agent", {**human, "budget": {}}, write=True)["after"].get("budget"), None)
        self.raises("unknown_role", ceiling.cap_role, path, "nope", human)
        self.raises("invalid_cap", ceiling.cap_role, path, "supervisor", {"actions": ["r*d"], "resources": []})

    def test_cap_role_random_never_wider_than_the_file(self):
        rng = random.Random(3)
        for _ in range(60):
            path = self.roles()
            name = rng.choice(["support-agent", "supervisor", "auditor", "break-glass"])
            old = tokens.Cap.from_json(json.loads(path.read_text())["roles"][name]["cap"])
            ceiling.cap_role(path, name, rand_cap(rng), write=True)
            new = tokens.Cap.from_json(json.loads(path.read_text())["roles"][name]["cap"])
            new.check_narrower_than(old)
            from sf_smartdelegate import bundle as b
            for n, rdef in json.loads(path.read_text())["roles"].items():
                b.Role(n, rdef)

    def test_capped_bundle_loads_and_binds(self):
        bundle_dir = Path(self.dir) / "bundle"
        shutil.copytree(BUNDLE, bundle_dir)
        ceiling.cap_role(bundle_dir / "roles.json", "support-agent", {"actions": ["read"], "resources": ["crm.customer/*"]}, write=True)
        e = Engine({**conformance_config(os.path.join(self.dir, "state")), "bundle_dir": str(bundle_dir)})
        self.addCleanup(e.close)
        self.assertEqual(core.delegate(e, user="alice", agent="support-bot", role="support-agent").capability.actions, ["read"])
        with self.assertRaises(EngineError) as cm:
            core.delegate(e, user="alice", agent="support-bot", role="support-agent", capability={"actions": ["update"], "resources": ["crm.customer/*"]})
        self.assertEqual(cm.exception.code, "role_exceeded")
        with mock.patch("os.replace", side_effect=OSError(28, "No space left on device")):
            self.raises("write_failed", ceiling.cap_role, bundle_dir / "roles.json", "auditor", {"actions": ["read"], "resources": ["*"]}, write=True)
        self.assertEqual(sorted(os.listdir(bundle_dir)), sorted(os.listdir(BUNDLE)))


# ---- command line ----------------------------------------------------------------------

EX = ROOT / "examples" / "bridges"


class Cli(Tmp):
    def run_cli(self, *args, env=None):
        return subprocess.run([*CLI, "bridge", *args], capture_output=True, text=True, env={**ENV, **(env or {})}, timeout=60)

    def ok(self, *args, env=None):
        p = self.run_cli(*args, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def fails(self, code, *args, env=None):
        p = self.run_cli(*args, env=env)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertEqual(p.stdout, "")
        self.assertIn(f"smartdelegate bridge: {code}: ", p.stderr)
        return p.stderr

    def write(self, name, value):
        path = Path(self.dir) / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def test_map_claims(self):
        g1 = "11111111-1111-1111-1111-111111111111"
        self.assertEqual(self.ok("map-claims", "--claims", json.dumps({"groups": [g1, "other"]}), "--rule", "@" + str(EX / "claims_rule.entra.json")),
                         {"groups": ["support"]})
        self.assertEqual(self.ok("map-claims", "--claims", "@" + self.write("c.json", {"groups": ["x"]}), "--map", self.write("m.json", {"x": "support"})),
                         {"groups": ["support"]})
        self.fails("claims_overage", "map-claims", "--claims", '{"hasgroups": true}', "--rule", "@" + str(EX / "claims_rule.entra.json"))
        self.fails("invalid_input", "map-claims", "--claims", "{not json", "--provider", "okta")
        self.fails("usage", "frobnicate")
        self.assertIn("sync-scim", self.run_cli("help").stdout)

    def test_generators_from_cap(self):
        cap = json.dumps({"actions": ["read"], "resources": ["s3.object/reports/*", "gcs.object/reports/*", "graph.mail/*"]})
        m = str(EX / "cloud_map.json")
        out = self.ok("aws-session-policy", "--cap", cap, "--map", m)
        self.assertEqual(out["policy"]["Statement"], [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::crm-exports/reports/*"]}])
        out = self.ok("gcp-boundary", "--cap", cap, "--map", m)
        self.assertEqual(len(out["boundary"]["accessBoundary"]["accessBoundaryRules"]), 1)
        out = self.ok("azure-scopes", "--cap", cap, "--map", m)
        self.assertEqual(out["by_resource"], {"https://graph.microsoft.com": ["https://graph.microsoft.com/Mail.Read"]})
        self.fails("empty_boundary", "gcp-boundary", "--cap", '{"actions": ["read"], "resources": ["crm.customer/*"]}', "--map", m)
        self.fails("map_invalid", "aws-session-policy", "--cap", cap, "--map", self.write("bad.json", {"aws": {"rule": []}}))
        self.fails("invalid_input", "aws-session-policy", "--cap", cap, "--map", m, "--role-arn", "arn:aws:iam::123456789012:role/x")

    def test_generators_from_a_verified_token(self):
        cfg = self.write("smartdelegate.json", conformance_config(os.path.join(self.dir, "state")))
        p = subprocess.run([*CLI, "token", "issue", "--user", "alice", "--agent", "support-bot", "--task", "ticket-1", "--config", cfg, "--raw",
                            "--cap", '{"actions": ["read"], "resources": ["s3.object/reports/*"]}'], capture_output=True, text=True, env=ENV, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        token = p.stdout.strip()
        m = str(EX / "cloud_map.json")
        out = self.ok("aws-session-policy", "--token", token, "--map", m, "--config", cfg, "--role-arn", "arn:aws:iam::123456789012:role/support")
        self.assertEqual(json.loads(out["assume_role"]["Policy"]), out["policy"])
        self.assertIn({"Key": "sd_user", "Value": "alice"}, out["assume_role"]["Tags"])
        self.assertIn({"Key": "sd_task", "Value": "ticket-1"}, out["assume_role"]["Tags"])
        # a forged token: the payload says more, the signature no longer matches
        head, body, sig = token.split(".")
        claims_ = json.loads(tokens.b64u_dec(body))
        claims_["cap"]["resources"] = ["*"]
        forged = f"{head}.{tokens.b64u(json.dumps(claims_).encode())}.{sig}"
        self.fails("token_invalid", "aws-session-policy", "--token", forged, "--map", m, "--config", cfg)
        p = self.run_cli("aws-session-policy", "--token", forged, "--unverified", "--map", m)
        self.assertEqual(p.returncode, 0, p.stderr)
        # which is exactly why --unverified is for inspection only: the forged payload yields a wider policy
        self.assertEqual(json.loads(p.stdout)["policy"]["Statement"][0]["Resource"], ["arn:aws:s3:::crm-exports/*"])
        self.assertIn("NOT checked", p.stderr)
        self.fails("invalid_input", "aws-session-policy", "--token", forged, "--map", m, "--role-arn", "arn:aws:iam::123456789012:role/support", "--unverified=true")
        subprocess.run([*CLI, "token", "revoke", "--token", token, "--config", cfg], capture_output=True, text=True, env=ENV, timeout=60)
        self.fails("token_invalid", "gcp-boundary", "--token", token, "--map", m, "--config", cfg)

    def test_ceiling(self):
        m = str(EX / "cloud_map.json")
        req = aws.simulation_request(MAP, "arn:aws:iam::123456789012:user/alice")
        results = [{"EvalActionName": a, "EvalResourceName": r, "EvalDecision": "allowed" if a != "s3:PutObject" else "implicitDeny"}
                   for a in req["ActionNames"] for r in req["ResourceArns"]]
        roles = Path(self.dir) / "roles.json"
        roles.write_text(json.dumps({"roles": {"exporter": {"members": [{"type": "Group", "id": "support"}],
                                                             "cap": {"actions": ["read", "update"], "resources": ["s3.object/reports/*"]}}}}))
        out = self.ok("ceiling", "--provider", "aws", "--results", "@" + self.write("r.json", results), "--map", m)
        self.assertEqual(out["cap"], {"actions": ["list", "read"], "resources": ["s3.object/*"]})
        out = self.ok("ceiling", "--provider", "aws", "--results", "@" + self.write("r.json", results), "--map", m, "--role", "exporter", "--roles", str(roles))
        self.assertEqual((out["role"]["after"], out["role"]["written"]), ({"actions": ["read"], "resources": ["s3.object/reports/*"]}, False))
        self.assertEqual(json.loads(roles.read_text())["roles"]["exporter"]["cap"]["actions"], ["read", "update"])
        out = self.ok("ceiling", "--provider", "aws", "--results", "@" + self.write("r.json", results), "--map", m, "--role", "exporter", "--roles", str(roles), "--write=true")
        self.assertTrue(out["role"]["written"])
        self.assertEqual(json.loads(roles.read_text())["roles"]["exporter"]["cap"], {"actions": ["read"], "resources": ["s3.object/reports/*"]})
        roles.write_text(json.dumps({"roles": {"exporter": {"members": [{"type": "Group", "id": "support"}],
                                                             "cap": {"actions": ["read", "update"], "resources": ["s3.object/a/*"]}}}}))
        out = self.ok("ceiling", "--provider", "aws", "--results", "@" + self.write("r.json", results), "--map", m, "--role", "exporter", "--roles", str(roles), "--write")
        self.assertTrue(out["role"]["written"])     # a bare trailing switch, through `python -m sf_smartdelegate bridge`
        self.assertEqual(json.loads(roles.read_text())["roles"]["exporter"]["cap"], {"actions": ["read"], "resources": ["s3.object/a/*"]})
        self.fails("invalid_input", "ceiling", "--provider", "oracle", "--results", "[]", "--map", m)
        self.fails("invalid_input", "ceiling", "--write=maybe", "--provider", "aws", "--results", "[]", "--map", m)

    def test_python_m_bridges_accepts_a_trailing_switch(self):
        roles = Path(self.dir) / "roles.json"
        roles.write_text(json.dumps({"roles": {"exporter": {"members": [{"type": "Group", "id": "support"}], "cap": {"actions": ["read", "update"], "resources": ["s3.object/*"]}}}}))
        results = [{"EvalActionName": "s3:GetObject", "EvalResourceName": "arn:aws:s3:::crm-exports/*", "EvalDecision": "allowed"}]
        p = subprocess.run([sys.executable, "-m", "sf_smartdelegate.bridges", "ceiling", "--provider", "aws", "--results", json.dumps(results),
                            "--map", str(EX / "cloud_map.json"), "--role", "exporter", "--roles", str(roles), "--write"],
                           capture_output=True, text=True, env=ENV, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(roles.read_text())["roles"]["exporter"]["cap"], {"actions": ["read"], "resources": ["s3.object/*"]})

    def test_sync_errors_from_the_command_line(self):
        bundle_dir = Path(self.dir) / "bundle"
        shutil.copytree(BUNDLE, bundle_dir)
        before = (bundle_dir / "entities.json").read_text()
        err = self.fails("no_credential", "sync-okta", "--org", "acme.okta.com", "--token-env", "OKTA_TOKEN_NOT_SET", "--out", str(bundle_dir))
        self.assertIn("OKTA_TOKEN_NOT_SET", err)
        self.fails("insecure_url", "sync-scim", "--url", "http://idp.example/scim/v2", "--token-env", "TOK", "--out", str(bundle_dir), env={"TOK": "x"})
        self.fails("invalid_input", "sync-scim", "--url", "https://idp.example/scim/v2", "--token-env", "TOK", env={"TOK": "x"})
        self.fails("no_credential", "sync-aws-identity-center", "--identity-store-id", "d-1234567890", "--region", "eu-west-1", "--out", str(bundle_dir),
                   env={"AWS_ACCESS_KEY_ID": "", "AWS_SECRET_ACCESS_KEY": ""})
        self.assertEqual((bundle_dir / "entities.json").read_text(), before)

    def test_sync_in_process_with_a_fake_directory(self):
        import contextlib
        import io
        bundle_dir = Path(self.dir) / "bundle"
        shutil.copytree(BUNDLE, bundle_dir)
        gm = self.write("gm.json", GROUP_MAP)
        argv = ["sync-okta", "--org", "acme.okta.com", "--token-env", "TOK", "--out", str(bundle_dir), "--group-map", gm]
        with mock.patch.dict(os.environ, {"TOK": fakes.TOKEN}):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(bridge_cli.main(argv + ["--dry-run"], transport=fakes.Okta()), 0)
            dry = json.loads(out.getvalue())
            self.assertEqual((dry["written"], dry["diff"]["users_removed"]), (False, ["dave"]))
            self.assertEqual((bundle_dir / "entities.json").read_text(), (BUNDLE / "entities.json").read_text())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(bridge_cli.main(argv, transport=fakes.Okta()), 0)
            self.assertEqual(json.loads((bundle_dir / "entities.sync.json").read_text())["source"], "okta:https://acme.okta.com")
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(bridge_cli.main(argv, transport=fakes.Okta(members={"g1": [], "g2": [], "g3": []})), 1)
            self.assertIn("removal_guard", err.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(bridge_cli.main(argv + ["--force"], transport=fakes.Okta(members={"g1": [], "g2": [], "g3": []})), 0)

    def sync_cli(self, argv, transport, env=None):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"TOK": fakes.TOKEN, **(env or {})}), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = bridge_cli.main(argv, transport=transport)
        return code, (json.loads(out.getvalue()) if out.getvalue() else None), err.getvalue()

    def test_sync_revoke_with_a_local_engine(self):
        bundle_dir = Path(self.dir) / "bundle"
        shutil.copytree(BUNDLE, bundle_dir)
        cfg_dict = {**conformance_config(os.path.join(self.dir, "state")), "bundle_dir": str(bundle_dir)}
        cfg = self.write("smartdelegate.json", cfg_dict)
        argv = ["sync-okta", "--org", "acme.okta.com", "--token-env", "TOK", "--out", str(bundle_dir), "--group-map", self.write("gm.json", GROUP_MAP)]
        code, out, _ = self.sync_cli(argv, fakes.Okta())
        self.assertEqual((code, out["would_revoke"]), (0, ["carol", "dave"]))   # reported, but --revoke was not given
        self.assertNotIn("revoked", out)
        self.assertEqual(len(out["reminders"]), 2)
        self.assertIn("reload", out["reminders"][0])
        self.assertIn("re-signed", out["reminders"][1])
        with Engine(cfg_dict) as e:
            tok = {u: e.issue_token("support-bot", user=u, role="support-agent", task="t")["token"] for u in ("alice", "bob", "erin")}
        gone = {"g1": ["u2", "u5"], "g2": [], "g3": ["u3"]}      # alice leaves support, bob leaves supervisors, erin stays
        code, out, _ = self.sync_cli(argv + ["--revoke", "--dry-run", "--force", "--config", cfg], fakes.Okta(members=gone))
        self.assertIsNotNone(out, _)
        self.assertEqual((code, out["written"], out["would_revoke"]), (0, False, ["alice", "bob"]))
        self.assertNotIn("revoked", out)
        with Engine(cfg_dict) as e:
            self.assertTrue(all(e.inspect_token(t)["valid"] for t in tok.values()))     # dry-run revoked nothing
        code, out, _ = self.sync_cli(argv + ["--config", cfg, "--force", "--revoke"], fakes.Okta(members=gone))   # 1 of 3 loses all groups: over the guard
        self.assertEqual((code, out["written"], out["revoked"]), (0, True, ["alice", "bob"]))
        with Engine(cfg_dict) as e:
            self.assertEqual({u: e.inspect_token(t).get("reason", "valid") for u, t in tok.items()},
                             {"alice": "token_revoked", "bob": "token_revoked", "erin": "valid"})
        # --revoke without an engine or daemon is refused before anything is fetched or written
        before = (bundle_dir / "entities.json").read_text()
        t = fakes.Okta()
        code, out, err = self.sync_cli(argv + ["--revoke", "--bundle", str(bundle_dir)], t)
        self.assertEqual((code, out, t.calls), (1, None, []))
        self.assertIn("state directory", err)
        self.assertEqual((bundle_dir / "entities.json").read_text(), before)

    def test_sync_revoke_and_reload_through_a_daemon(self):
        bundle_dir = Path(self.dir) / "bundle"
        shutil.copytree(BUNDLE, bundle_dir)
        argv = ["sync-okta", "--org", "acme.okta.com", "--token-env", "TOK", "--out", str(bundle_dir), "--group-map", self.write("gm.json", GROUP_MAP)]
        with Daemon(extra={"bundle_dir": str(bundle_dir)}) as d:
            client = DaemonClient(d.url, admin_key=Daemon.ADMIN)
            before = client.call("info", {})["policy_version"]
            tok = {u: client.issue_token("support-bot", user=u, role=r, task="t")["token"] for u, r in (("alice", "support-agent"), ("carol", "auditor"))}
            via = ["--daemon-url", d.url, "--admin-key-env", "ADM"]
            code, out, _ = self.sync_cli(argv + via + ["--revoke", "--dry-run"], fakes.Okta(), {"ADM": Daemon.ADMIN})
            self.assertEqual((code, out["would_revoke"], "reload" in out), (0, ["carol", "dave"], False))
            self.assertEqual(client.call("info", {})["policy_version"], before)
            self.assertTrue(client.inspect_token(tok["carol"])["valid"])
            code, out, err = self.sync_cli(argv + via + ["--revoke"], fakes.Okta(), {"ADM": Daemon.ADMIN})
            self.assertEqual(code, 0, err)
            self.assertEqual(out["revoked"], ["carol", "dave"])     # carol lost compliance, dave was removed
            self.assertEqual(out["reload"], {"ok": True, "policy_version": client.call("info", {})["policy_version"]})
            self.assertNotEqual(out["reload"]["policy_version"], before)
            self.assertEqual(len(out["reminders"]), 1)              # the reload was done; re-signing is still the operator's
            self.assertEqual(client.inspect_token(tok["carol"])["reason"], "token_revoked")
            self.assertTrue(client.inspect_token(tok["alice"])["valid"])
            r = client.call("issue_token", {"agent": "support-bot", "user": "carol", "role": "auditor"})   # and the daemon sees the new membership
            self.assertEqual(r["error"]["code"], "role_not_held")
            # a wrong admin key: the file is written, the failure is reported exactly, the exit code is 1
            gone = {"g1": ["u2", "u5"], "g2": ["u2"], "g3": ["u3"]}
            code, out, err = self.sync_cli(argv + via + ["--revoke", "--force"], fakes.Okta(members=gone), {"ADM": "wrong-key"})
            self.assertIsNotNone(out, err)
            self.assertEqual((code, out["written"], out["revoked"], out["not_revoked"], out["reload"]["ok"]), (1, True, [], ["alice"], False))
            self.assertIn("entities.json WAS written", err)
            self.assertIn("NOT revoked: alice", err)
            self.assertNotIn("wrong-key", err + json.dumps(out))
            self.assertTrue(client.inspect_token(tok["alice"])["valid"])
        code, out, err = self.sync_cli(argv + ["--daemon-url", "http://daemon.example:8181", "--admin-key-env", "ADM"], fakes.Okta(), {"ADM": "k"})
        self.assertEqual(code, 1)
        self.assertIn("insecure_url", err)

    def test_sync_scim_end_to_end_over_loopback(self):
        """The real CLI and the real urllib transport against a SCIM fake on 127.0.0.1."""
        fake = fakes.Scim()
        fake.host = "127.0.0.1"

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                status, headers, body = fake("GET", f"http://127.0.0.1{self.path}", {"Authorization": self.headers.get("Authorization")}, None)
                self.send_response(status)
                self.send_header("Content-Type", "application/scim+json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        server.daemon_threads = True
        t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        bundle_dir = Path(self.dir) / "bundle"
        shutil.copytree(BUNDLE, bundle_dir)
        env = {k: "" for k in os.environ if k.lower().endswith("_proxy")}
        out = self.ok("sync-scim", "--url", f"http://127.0.0.1:{server.server_port}/scim/v2", "--token-env", "TOK", "--out", str(bundle_dir),
                      "--group-map", self.write("gm.json", GROUP_MAP), env={**env, "TOK": fakes.TOKEN, "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"})
        self.assertTrue(out["written"])
        self.assertEqual(out["diff"]["users_removed"], ["dave"])
        self.assertNotIn(fakes.TOKEN, json.dumps(out))
        cfg = self.write("smartdelegate.json", {**conformance_config(os.path.join(self.dir, "state")), "bundle_dir": str(bundle_dir)})
        p = subprocess.run([*CLI, "token", "issue", "--user", "carol", "--agent", "support-bot", "--role", "support-agent", "--config", cfg],
                           capture_output=True, text=True, env=ENV, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_walkthrough_example_runs(self):
        p = subprocess.run([sys.executable, str(EX / "walkthrough.py")], capture_output=True, text=True, env=ENV, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("DELEGATE-ROLE-NOT-HELD", p.stdout)
        self.assertEqual(p.stdout.count("DELEGATE-TOKEN-REVOKED"), 2)
        self.assertIn("sd_task=ticket-7", p.stdout)
        self.assertIn("arn:aws:s3:::crm-exports/reports/*", p.stdout)


class Hygiene(unittest.TestCase):
    def test_standard_library_only(self):
        """No cloud SDK or third-party HTTP library is imported by the bridges."""
        banned = re.compile(r"^\s*(import|from)\s+(boto3|botocore|google|azure|msal|requests|httpx|urllib3|okta)\b", re.M)
        for f in sorted((ROOT / "src" / "sf_smartdelegate" / "bridges").glob("*.py")):
            self.assertIsNone(banned.search(f.read_text(encoding="utf-8")), f.name)

    def test_every_adapter_says_it_was_not_run_against_the_real_service(self):
        for name in ("scim", "okta", "entra", "google", "aws_identity_center", "aws", "gcp", "azure", "claims"):
            text = (ROOT / "src" / "sf_smartdelegate" / "bridges" / f"{name}.py").read_text(encoding="utf-8")
            self.assertRegex(text, r"https://", name)
            self.assertRegex(text, r"(was not contacted|No [\w ]+ was contacted|none was run against)", name)

    def test_keycloak_says_which_real_server_it_was_run_against(self):
        """Keycloak is the one provider with a live suite (live/idp/). The claim
        names the version and stays honest about the rest."""
        for name in ("keycloak", "claims"):
            text = (ROOT / "src" / "sf_smartdelegate" / "bridges" / f"{name}.py").read_text(encoding="utf-8")
            self.assertRegex(text, r"real Keycloak \d+\.\d+\.\d+ \(live/idp/, \d{4}-\d\d-\d\d\)", name)
        self.assertRegex((ROOT / "src" / "sf_smartdelegate" / "bridges" / "keycloak.py").read_text(encoding="utf-8"), r"# UNVERIFIED: Keycloak versions other than")
        self.assertTrue((ROOT / "live" / "idp" / "test_live_idp.py").is_file())


if __name__ == "__main__":
    unittest.main()
