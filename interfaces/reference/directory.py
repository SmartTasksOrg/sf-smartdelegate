"""Reference DirectorySource: the SCIM 2.0 adapter of sf_smartdelegate.bridges,
and the one call that turns any DirectorySource into entities.json.

The other adapters (okta, entra, keycloak, google, aws_identity_center) return
the same Snapshot; wrap them the same way. docs/BRIDGES.md says which were
run against a real service.
"""
from __future__ import annotations

from sf_smartdelegate.bridges import BridgeError, directory, scim
from sf_smartdelegate.bridges.http import Transport, urllib_transport

from ..contracts import DirectoryError, DirectorySource


class ScimDirectorySource:
    def __init__(self, base_url: str, token_env: str, *, transport: Transport = urllib_transport, env=None):
        """`token_env` names the environment variable holding the bearer
        token; the token itself is never passed, stored or printed."""
        self.base_url, self.token_env, self.transport, self.env = base_url, token_env, transport, env

    def snapshot(self) -> directory.Snapshot:
        try:
            return scim.fetch(self.base_url, token_env=self.token_env, transport=self.transport, env=self.env)
        except BridgeError as e:
            raise DirectoryError(e.code, e.message) from None


def sync_directory(source: DirectorySource, entities_path, *, backend=None, revoke_by: str = "sync", **options) -> dict:
    """snapshot -> entities.json, with the guarded atomic write of
    sf_smartdelegate.bridges.directory.sync (`options`: group_map, attr_map,
    user_id, group_id, dry_run, force, max_removal_fraction).

    With `backend` (an Engine or a DaemonClient with the admin key) and a
    write that happened: reload first, then end the live tokens of every user
    who was removed or lost a group. The order matters: an engine that has not
    reloaded can issue a new token from the old membership after the revoke."""
    result = directory.sync(source.snapshot(), entities_path, **options)
    if backend is not None and result["written"]:
        reloaded = backend.call("reload", {})
        if not reloaded.get("ok"):
            raise DirectoryError("reload_failed", "entities.json was written, but the engine did not reload it "
                                 f"({(reloaded.get('error') or {}).get('code')}); nobody was revoked")
        result["revoked"] = directory.revoke_changed(backend, result["diff"], by=revoke_by)["revoked"]
    return result
