"""Bridges between SmartDelegate and real IAM systems. See docs/BRIDGES.md.

Inbound (the agent's bound follows the human's):

    claims      verified ID/access-token claims -> the `groups` list for issue_token
    directory   a directory snapshot -> entities.json (atomic, guarded write)
    scim, okta, entra, keycloak, google, aws_identity_center
                read users, groups and memberships into a `directory.Snapshot`
    ceiling     what the human may do in the cloud -> a cap on a role's ceiling

Outbound (a cloud credential no wider than the SmartDelegate token):

    aws         STS AssumeRole kwargs with a generated session policy and tags
    gcp         Credential Access Boundary + STS token exchange (Cloud Storage only)
    azure       On-Behalf-Of request with the scopes the cap maps to

Everything here is standard library only. Network calls go through an
injectable `http.Transport`; functions for a cloud SDK return plain dicts and
never import the SDK.

STATUS: every adapter was written from the provider's public documentation
and, except for Keycloak, has been run only against fake servers in tests/.
The Keycloak adapter and claim rules are verified against a real server
(live/idp). Nothing here has been run against a real AWS, Azure, Google or
Okta service. Details that
could not be checked in the documentation are marked `# UNVERIFIED:` in the
code and listed in docs/BRIDGES.md.
"""
from __future__ import annotations


class BridgeError(Exception):
    """A bridge could not do what was asked. Bridges fail closed: an HTTP
    error, a malformed or truncated response, or an unexpected shape raises
    this instead of returning a partial answer. `code` is stable and short;
    `message` never contains a credential."""

    def __init__(self, code: str, message: str, detail=None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        #: optional structured data for the caller (never a secret)
        self.detail = detail


from . import http  # noqa: E402
from . import claims, cloudmap, directory, ceiling  # noqa: E402
from . import scim, okta, entra, keycloak, google, sigv4, aws_identity_center  # noqa: E402
from . import aws, gcp, azure  # noqa: E402
from .claims import groups_from_claims  # noqa: E402
from .directory import Group, Snapshot, User, diff, revoke_changed, sync, to_entities, users_to_revoke, write_entities  # noqa: E402
from .http import Transport, urllib_transport  # noqa: E402

__all__ = ["BridgeError", "Transport", "urllib_transport", "groups_from_claims", "Snapshot", "User", "Group",
           "to_entities", "diff", "write_entities", "sync", "revoke_changed", "users_to_revoke", "http", "claims", "cloudmap", "directory", "ceiling",
           "scim", "okta", "entra", "keycloak", "google", "sigv4", "aws_identity_center", "aws", "gcp", "azure"]
