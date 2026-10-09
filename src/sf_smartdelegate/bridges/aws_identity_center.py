"""AWS IAM Identity Center directory adapter (Identity Store API).

Written from:
  https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_ListGroups.html
      request IdentityStoreId, MaxResults (1-100), NextToken -> Groups[] {GroupId, DisplayName}, NextToken
  https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_ListGroupMemberships.html
      request GroupId, IdentityStoreId, MaxResults (1-100), NextToken ->
      GroupMemberships[] {GroupId, MemberId: {UserId}}, NextToken
  https://docs.aws.amazon.com/pdfs/singlesignon/latest/IdentityStoreAPIReference/identitystore-api.pdf
      ListUsers: IdentityStoreId, MaxResults, NextToken -> Users[] {UserId, UserName, DisplayName, ...}
  https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html
      UserStatus: ENABLED | DISABLED
Requests are JSON-1.1 POSTs signed with `sigv4.sign`. Credentials come from the standard
environment variables AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN.
Tested only against the fake Identity Store in tests/. AWS was not contacted.

# UNVERIFIED: the wire details below are not in the API reference pages that were read.
#   - endpoint  https://identitystore.<region>.amazonaws.com/            (from memory)
#   - signing service name "identitystore"                               (from memory)
#   - X-Amz-Target "AWSIdentityStore.<Operation>" and Content-Type application/x-amz-json-1.1
#     (seen only in a third-party SDK's source, amazonka-identitystore, not in AWS's pages)
# UNVERIFIED: whether ListUsers returns UserStatus (the data type has it; the ListUsers page
# read did not show it). A user without UserStatus is treated as enabled.
# UNVERIFIED: that Identity Center groups cannot contain groups (MemberId is read as UserId only).
If any of this is wrong the adapter fails with an HTTP error; it cannot return wrong members.
Using boto3's identitystore client and building the Snapshot yourself avoids these doubts.
"""
from __future__ import annotations

import json
import os
import re

from . import BridgeError, sigv4
from .directory import Group, Snapshot, User
from .http import PageGuard, Transport, request_json, str_field, urllib_transport

_REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-\d")


def _call(transport: Transport, url: str, region: str, creds: tuple, op: str, payload: dict, now=None) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = sigv4.sign("POST", url, {"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": f"AWSIdentityStore.{op}"}, body,
                         access_key=creds[0], secret_key=creds[1], session_token=creds[2], region=region, service="identitystore", now=now)
    answer, _ = request_json(transport, "POST", url, headers, body)
    if not isinstance(answer, dict):
        raise BridgeError("malformed_response", f"{op}: expected a JSON object")
    return answer


def _list(transport, url, region, creds, op: str, key: str, payload: dict, max_pages: int, now=None) -> list:
    """Every item under `key` of a NextToken listing. A repeated token raises."""
    guard = PageGuard(url, max_pages)
    token, out = None, []
    while True:
        guard.step(token)
        page = _call(transport, url, region, creds, op, {**payload, "MaxResults": 100, **({"NextToken": token} if token else {})}, now)
        if not isinstance(page.get(key), list):
            raise BridgeError("malformed_response", f"{op}: '{key}' is missing or not a list")
        out.extend(page[key])
        token = page.get("NextToken")
        if token is None or token == "":
            return out
        if not isinstance(token, str):
            raise BridgeError("malformed_response", f"{op}: NextToken is not a string")


def fetch(identity_store_id: str, region: str, *, transport: Transport = urllib_transport, max_pages: int = 10000,
          env=None, now=None) -> Snapshot:
    """Users, groups and memberships of an IAM Identity Center identity store.

    Read-only IAM permissions needed: identitystore:ListUsers,
    identitystore:ListGroups, identitystore:ListGroupMemberships. Guarantees:
    every listing follows NextToken to the end; a user with UserStatus
    DISABLED is inactive; members that the user listing did not return are
    ignored; any HTTP error or malformed page raises."""
    if not isinstance(region, str) or not _REGION.fullmatch(region):
        raise BridgeError("invalid_input", "region is not an AWS region name")
    if not isinstance(identity_store_id, str) or not identity_store_id:
        raise BridgeError("invalid_input", "identity_store_id is required")
    env = os.environ if env is None else env
    creds = (env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY"), env.get("AWS_SESSION_TOKEN") or None)
    if not creds[0] or not creds[1]:
        raise BridgeError("no_credential", "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set")
    url = f"https://identitystore.{region}.amazonaws.com/"
    base = {"IdentityStoreId": identity_store_id}
    snap = Snapshot(source=f"aws-identity-center:{identity_store_id}")
    for u in _list(transport, url, region, creds, "ListUsers", "Users", base, max_pages, now):
        uid = str_field(u, "UserId", "Identity Store user")
        attrs = {k: u[k] for k in ("UserName", "DisplayName", "Title", "UserType") if isinstance(u.get(k), str)}
        emails = [e for e in (u.get("Emails") or []) if isinstance(e, dict) and isinstance(e.get("Value"), str)]
        if emails:
            attrs["email"] = next((e["Value"] for e in emails if e.get("Primary") is True), emails[0]["Value"])
        snap.users[uid] = User(uid, str_field(u, "UserName", "Identity Store user"), u.get("UserStatus", "ENABLED") == "ENABLED", attrs)
    for g in _list(transport, url, region, creds, "ListGroups", "Groups", base, max_pages, now):
        gid = str_field(g, "GroupId", "Identity Store group")
        snap.groups[gid] = Group(gid, str_field(g, "DisplayName", "Identity Store group"))
    for gid in sorted(snap.groups):
        for m in _list(transport, url, region, creds, "ListGroupMemberships", "GroupMemberships", {**base, "GroupId": gid}, max_pages, now):
            member = m.get("MemberId") if isinstance(m, dict) else None
            if not isinstance(member, dict):
                raise BridgeError("malformed_response", "ListGroupMemberships: 'MemberId' is missing")
            if member.get("UserId") in snap.users:
                snap.add_member(member["UserId"], gid)
    return snap
