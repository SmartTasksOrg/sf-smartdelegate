"""Fake identity providers for the bridge tests: in-process transport
functions (no sockets) that implement each provider's documented pagination
and response shapes over one small directory.

    alice, bob, erin   in "support"          dave is disabled
    bob                in "supervisors"
    carol              in "emea", and "emea" is nested in "support"

`mode` breaks a fake on purpose: "http429", "http500", "malformed", "loop"
(a next page that never ends), "foreign" (a next link to another host),
"truncated" (fewer items than the server says there are).
"""
import json
import urllib.parse

USERS = [("u1", "alice", True), ("u2", "bob", True), ("u3", "carol", True), ("u4", "dave", False), ("u5", "erin", True)]
GROUPS = {"g1": ("support", ["u1", "u2", "u5"], []), "g2": ("supervisors", ["u2"], []), "g3": ("emea", ["u3"], ["g1"])}
TOKEN = "s3cr3t-token-value"


def js(status, value, headers=None):
    return status, {"content-type": "application/json", **(headers or {})}, json.dumps(value).encode()


class Fake:
    """Base: records calls, checks the credential, applies `mode`."""
    host = "idp.example"
    auth = "Bearer " + TOKEN

    def __init__(self, mode=None, page=2, members=None):
        self.mode, self.page, self.calls = mode, page, []
        self.members = {g: list(v[1]) for g, v in GROUPS.items()} if members is None else members

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url))
        u = urllib.parse.urlsplit(url)
        if u.hostname != self.host:
            raise AssertionError(f"the bridge sent a request to {u.hostname}")
        if not self.check_auth(headers):
            return js(401, {"error": "unauthorized"})
        if self.mode == "http429":
            return js(429, {"error": "rate limited"}, {"retry-after": "1"})
        if self.mode == "http500":
            return js(500, {"error": "boom"})
        if self.mode == "malformed" and len(self.calls) >= 2:
            return 200, {}, b'{"this is": "cut off'
        return self.route(method, u, dict(urllib.parse.parse_qsl(u.query)), body)

    def check_auth(self, headers):
        return headers.get("Authorization") == self.auth


class Scim(Fake):
    def route(self, method, u, q, body):
        start, count = int(q.get("startIndex", 1)), min(int(q.get("count", 100)), self.page)
        if u.path.endswith("/Users"):
            items = [{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "id": i, "userName": n, "active": a,
                      "emails": [{"value": n + "@example.com", "primary": True}],
                      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "EU" if n != "carol" else "US"}}
                     for i, n, a in USERS]
        elif u.path.endswith("/Groups"):
            items = [{"id": g, "displayName": name,
                      "members": [{"value": m, "type": "User", "$ref": f"https://{self.host}/scim/v2/Users/{m}"} for m in self.members[g]]
                      + [{"value": c, "$ref": f"https://{self.host}/scim/v2/Groups/{c}"} for c, v in GROUPS.items() if g in v[2]]}
                     for g, (name, _, _) in GROUPS.items()]
        else:
            return js(404, {})
        if self.mode == "loop":
            start = 1
        page = items[start - 1:start - 1 + count]
        if self.mode == "truncated" and start > 1:
            page = []
        return js(200, {"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": len(items),
                        "startIndex": start, "itemsPerPage": len(page), "Resources": page})


class Okta(Fake):
    host = "acme.okta.com"
    auth = "SSWS " + TOKEN

    def route(self, method, u, q, body):
        if u.path == "/api/v1/users":
            items = [{"id": i, "status": "ACTIVE" if a else "SUSPENDED", "profile": {"login": n, "email": n + "@example.com"}} for i, n, a in USERS]
        elif u.path == "/api/v1/groups":
            items = [{"id": g, "type": "OKTA_GROUP", "profile": {"name": name}} for g, (name, _, _) in GROUPS.items()]
        elif u.path.endswith("/users"):
            g = u.path.split("/")[4]
            items = [{"id": m, "status": "ACTIVE", "profile": {"login": m}} for m in self.members[g]]
        else:
            return js(404, {})
        after = int(q.get("after", 0))
        page = items[after:after + self.page]
        base = f"https://{self.host}{u.path}?limit=200"
        links = [f'<{base}&after={after}>; rel="self"']
        if self.mode == "loop":
            links.append(f'<{base}&after={after}>; rel="next"')
        elif self.mode == "foreign" and u.path == "/api/v1/users":
            links.append('<https://evil.example/api/v1/users?after=2>; rel="next"')
        elif after + self.page < len(items):
            links.append(f'<{base}&after={after + self.page}>; rel="next"')
        return js(200, page, {"link": ", ".join(links)})


class Graph(Fake):
    host = "graph.microsoft.com"

    def __init__(self, *a, with_type=True, **kw):
        super().__init__(*a, **kw)
        self.with_type = with_type

    def descendants(self, g):
        out, kids = [], [c for c, v in GROUPS.items() if g in v[2]]
        for c in kids:
            out += [c] + self.descendants(c)
        return out

    def route(self, method, u, q, body):
        path = u.path[len("/v1.0"):]
        if method == "POST" and path.endswith("/getMemberGroups"):
            uid = path.split("/")[2]
            direct = [g for g in GROUPS if uid in self.members[g]]
            allg = set(direct)
            for g in direct:
                allg |= set(GROUPS[g][2])
            out = {"value": sorted(allg)}
            if self.mode == "truncated":
                out["@odata.nextLink"] = f"https://{self.host}/v1.0/more"
            return js(200, out)
        tag = lambda t, d: ({"@odata.type": t, **d} if self.with_type else d)
        if path == "/users":
            assert "accountEnabled" in q["$select"], "accountEnabled must be selected"
            items = [{"id": i, "userPrincipalName": n + "@example.com", "displayName": n.title(), "accountEnabled": a, "department": "EU"} for i, n, a in USERS]
        elif path == "/groups":
            items = [{"id": g, "displayName": name, "securityEnabled": True} for g, (name, _, _) in GROUPS.items()]
        elif path.endswith("/transitiveMembers"):
            g = path.split("/")[2]
            items = [tag("#microsoft.graph.user", {"id": m}) for m in self.members[g]]
            for c in self.descendants(g):
                items.append(tag("#microsoft.graph.group", {"id": c}))
                items += [tag("#microsoft.graph.user", {"id": m}) for m in self.members[c]]
            items.append({"@odata.type": "#microsoft.graph.device", "id": "dev1"})
        elif path.endswith("/members"):
            g = path.split("/")[2]
            items = [tag("#microsoft.graph.user", {"id": m}) for m in self.members[g]]
            items += [tag("#microsoft.graph.group", {"id": c}) for c, v in GROUPS.items() if g in v[2]]
        else:
            return js(404, {})
        skip = int(q.get("$skiptoken", 0))
        out = {"value": items[skip:skip + self.page]}
        nxt = f"https://{self.host}{u.path}?$select={q.get('$select', 'id')}&$top=999&$skiptoken="
        if self.mode == "loop":
            out["@odata.nextLink"] = nxt + str(skip)
        elif self.mode == "foreign" and path == "/users":
            out["@odata.nextLink"] = "https://graph.evil.example/v1.0/users?$skiptoken=2"
        elif skip + self.page < len(items):
            out["@odata.nextLink"] = nxt + str(skip + self.page)
        return js(200, out)


class EntraLogin:
    """login.microsoftonline.com token endpoint: client credentials only."""

    def __init__(self, secret="app-secret-value"):
        self.secret, self.calls = secret, []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url))
        form = dict(urllib.parse.parse_qsl((body or b"").decode()))
        if urllib.parse.urlsplit(url).hostname != "login.microsoftonline.com" or method != "POST":
            return js(404, {})
        if form.get("grant_type") != "client_credentials" or form.get("client_secret") != self.secret:
            return js(401, {"error": "invalid_client", "error_description": f"bad secret {form.get('client_secret')}"})
        return js(200, {"token_type": "Bearer", "expires_in": 3599, "access_token": TOKEN})


class Keycloak(Fake):
    """Shapes as a real Keycloak 26.0.7 returned them (live/idp/, 2026-10-05):

    * GET /groups carries `"subGroups": []` next to `subGroupCount`; the children come from
      /groups/{id}/children and carry `parentId` (`children_endpoint=True`, the real behaviour).
      `children_endpoint=False` is the older shape with `subGroups` filled in; no such server
      was contacted.
    * mode "underprivileged": what a credential with query-users + query-groups but without
      view-users gets: HTTP 200, empty listings, a count of 0. Mode "underprivileged_count":
      the same on Keycloak 26.8.0, where /users/count still answers the real number.
    * `impostor=True`: a top-level group NAMED "support/emea". Keycloak does not escape the
      slash, so its path equals that of the subgroup emea of support.
    * the token endpoint answers the client-credentials grant of a service account.
    """
    host = "kc.example"
    SECRET = "kc-client-secret-value"

    def __init__(self, *a, children_endpoint=True, impostor=False, **kw):
        super().__init__(*a, **kw)
        self.children_endpoint = children_endpoint
        self.impostor = impostor

    def check_auth(self, headers):
        return self.calls[-1][1].endswith("/protocol/openid-connect/token") or super().check_auth(headers)

    def group(self, g, parent_path="", parent=None):
        path = parent_path + "/" + GROUPS[g][0]
        kids = [self.group(c, path, g)[0] for c, v in GROUPS.items() if g in v[2]]
        out = {"id": g, "name": GROUPS[g][0], "path": path, "subGroupCount": len(kids),
               "subGroups": [] if self.children_endpoint else kids,
               "access": {"view": True, "viewMembers": True, "manageMembers": False, "manage": False, "manageMembership": False}}
        if parent:
            out["parentId"] = parent
        return out, kids

    def route(self, method, u, q, body):
        if u.path == "/realms/acme/protocol/openid-connect/token":
            form = dict(urllib.parse.parse_qsl((body or b"").decode()))
            if method != "POST" or form.get("grant_type") != "client_credentials" or form.get("client_id") != "sd-sync" or form.get("client_secret") != self.SECRET:
                return js(401, {"error": "unauthorized_client", "error_description": "Invalid client or Invalid client credentials"})
            return js(200, {"access_token": TOKEN, "expires_in": 300, "refresh_expires_in": 0, "token_type": "Bearer", "not-before-policy": 0, "scope": "email profile"})
        path = u.path.split("/admin/realms/acme", 1)[1]
        hidden = self.mode in ("underprivileged", "underprivileged_count")
        if path == "/users/count":
            return js(200, 0 if self.mode == "underprivileged" else len(USERS) + (3 if self.mode == "truncated" else 0))
        if path == "/users":
            items = [{"id": i, "username": n, "enabled": a, "email": n + "@example.com", "emailVerified": True, "attributes": {"region": ["EU"]},
                      "createdTimestamp": 1791212934302, "totp": False, "disableableCredentialTypes": [], "requiredActions": [], "notBefore": 0,
                      "access": {"manageGroupMembership": False, "view": True, "mapRoles": False, "impersonate": False, "manage": False}}
                     for i, n, a in USERS]
        elif path == "/groups":
            items = [self.group(g)[0] for g, v in GROUPS.items() if not v[2]]
            if self.impostor:
                items.append({"id": "g9", "name": "support/emea", "path": "/support/emea", "subGroupCount": 0, "subGroups": []})
        elif path.endswith("/children"):
            items = [k for k in self.group(path.split("/")[2])[1]]
        elif path.endswith("/members"):
            items = [{"id": m, "username": m} for m in self.members.get(path.split("/")[2], [])]
        else:
            return js(404, {})
        if hidden:
            items = []
        first, mx = (0 if self.mode == "loop" else int(q.get("first", 0))), min(int(q.get("max", 100)), self.page)
        return js(200, items[first:first + mx])


class Google(Fake):
    host = "admin.googleapis.com"

    def route(self, method, u, q, body):
        path = u.path[len("/admin/directory/v1"):]
        if path == "/users":
            key, items = "users", [{"id": i, "primaryEmail": n + "@example.com", "suspended": not a, "name": {"fullName": n.title()},
                                    "orgUnitPath": "/EU"} for i, n, a in USERS]
        elif path == "/groups":
            key, items = "groups", [{"id": g, "email": name + "@example.com", "name": name} for g, (name, _, _) in GROUPS.items()]
        elif path.endswith("/members"):
            g = path.split("/")[2]
            key, items = "members", [{"id": m, "type": "USER", "role": "MEMBER"} for m in self.members[g]]
            items += [{"id": c, "type": "GROUP"} for c, v in GROUPS.items() if g in v[2]]
            items.append({"id": "x9", "type": "EXTERNAL", "email": "someone@elsewhere.example"})
            if g == "g2":
                items.append({"id": "C0123", "type": "CUSTOMER"})   # "all users in the domain": must grant nothing
        else:
            return js(404, {})
        at = int(q.get("pageToken", "t0")[1:])
        out = {"kind": "admin#directory#" + key, key: items[at:at + self.page]}
        if self.mode == "loop":
            out["nextPageToken"] = "t0"
        elif at + self.page < len(items):
            out["nextPageToken"] = f"t{at + self.page}"
        return js(200, out)


class IdentityStore(Fake):
    host = "identitystore.eu-west-1.amazonaws.com"

    def check_auth(self, headers):
        a = headers.get("Authorization", "")
        return (a.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") and "/eu-west-1/identitystore/aws4_request" in a
                and "x-amz-target" in a and headers.get("Content-Type") == "application/x-amz-json-1.1"
                and headers.get("X-Amz-Security-Token") == "session-token")

    def __call__(self, method, url, headers, body):
        self.headers = headers
        return super().__call__(method, url, headers, body)

    def route(self, method, u, q, body):
        req, op = json.loads(body), self.headers["X-Amz-Target"].split(".")[1]
        assert method == "POST" and req["IdentityStoreId"] == "d-1234567890"
        if op == "ListUsers":
            key, items = "Users", [{"UserId": i, "UserName": n, "UserStatus": "ENABLED" if a else "DISABLED",
                                    "Emails": [{"Value": n + "@example.com", "Primary": True}]} for i, n, a in USERS]
        elif op == "ListGroups":
            key, items = "Groups", [{"GroupId": g, "DisplayName": name} for g, (name, _, _) in GROUPS.items()]
        elif op == "ListGroupMemberships":
            key, items = "GroupMemberships", [{"GroupId": req["GroupId"], "MemberId": {"UserId": m}} for m in self.members[req["GroupId"]]]
        else:
            return js(400, {"__type": "UnknownOperationException"})
        at = int(req.get("NextToken", "0"))
        out = {key: items[at:at + self.page]}
        if self.mode == "loop":
            out["NextToken"] = "1"
        elif at + self.page < len(items):
            out["NextToken"] = str(at + self.page)
        return js(200, out)
