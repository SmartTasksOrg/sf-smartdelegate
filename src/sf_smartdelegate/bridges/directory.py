"""The common directory snapshot, and the guarded writer of entities.json.

Every directory adapter returns a `Snapshot`. `to_entities` turns it into
the entity list of a bundle, `write_entities` writes it so that a broken
directory response can neither leave half a file behind nor silently strip
everybody's access:

  * the new file is written next to the old one, loaded with
    `sf_smartdelegate.cedar.Store`, and only then moved into place (os.replace);
  * a sync that would remove more than `max_removal_fraction` of the existing
    users - or leave more than that fraction of the users who had groups with
    none - aborts unless `force=True`.

The opposite risk is not solved by the writer: when the sync does not run,
a removed human keeps the membership that is on disk. `entities.sync.json`
(next to entities.json) records when the last sync ran so that staleness can
be monitored. See docs/BRIDGES.md, "Freshness".
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .. import cedar
from . import BridgeError


@dataclass
class User:
    """A human in the directory. `name` is the login name; `attrs` is whatever
    the adapter read (flat where possible)."""
    id: str
    name: str
    active: bool = True
    attrs: dict = field(default_factory=dict)


@dataclass
class Group:
    """A directory group. `parents` are the ids of the groups it is nested in."""
    id: str
    name: str
    parents: set = field(default_factory=set)


@dataclass
class Snapshot:
    """Users, groups and memberships (user id -> ids of the groups the user is
    a direct member of) as read from one directory at one time."""
    users: dict = field(default_factory=dict)
    groups: dict = field(default_factory=dict)
    memberships: dict = field(default_factory=dict)
    source: str = ""

    def add_member(self, user_id: str, group_id: str) -> None:
        self.memberships.setdefault(user_id, set()).add(group_id)


def _path(obj: dict, path: str):
    if path in obj:
        return obj[path]
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _ident(kind: str, obj, how: str) -> str:
    v = obj.name if how == "name" else obj.id if how == "id" else _path(getattr(obj, "attrs", {}) or {}, how)
    if not isinstance(v, str) or not v:
        raise BridgeError("id_missing", f"{kind} {obj.id!r} has no usable '{how}' to serve as its entity id")
    return v


def _attr_ok(v) -> bool:
    return isinstance(v, (str, bool)) or (isinstance(v, int)) or (isinstance(v, list) and all(isinstance(x, str) for x in v))


def to_entities(snapshot: Snapshot, existing_entities: list, *, user_id: str = "name", group_id: str = "name",
                group_map: dict | None = None, attr_map: dict | None = None, user_type: str = "User",
                group_type: str = "Group") -> list:
    """The entity list for entities.json: the directory's users and groups,
    plus every existing entity whose type is neither `user_type` nor
    `group_type` (agents, agent groups, ...) unchanged and in its old order.

    user_id / group_id  "name", "id", or (users) a path into `User.attrs`: what becomes the entity id.
    group_map           {directory group id or name -> SmartDelegate group id}. When given, groups
                        not in it are dropped. A user nested below a dropped group still reaches
                        the mapped groups above it.
    attr_map            {entity attribute -> path into User.attrs}. Only these attributes are
                        written; attributes that existing User entities had are NOT carried over.

    Guarantees: inactive users are left out; nested groups become `parents`;
    output order is groups by id, users by id, then the kept entities; the
    same snapshot always gives the same list. Two directory users that would
    get the same entity id, a membership naming an unknown group, or an
    attribute that is not a string, integer, boolean or list of strings raise
    BridgeError: none of them is guessed at. So do two DIFFERENT directory
    groups that carry the same name and are identified by it (`group_id`
    "name" without a map, or a map entry keyed by that name):
    BridgeError("duplicate_group"). Several groups become one entity only
    when the map names each of them by its directory id, or by different names."""
    for name, t in (("user_type", user_type), ("group_type", group_type)):
        if not cedar.valid_type(t):
            raise BridgeError("invalid_input", f"{name} is not a valid entity type")
    if user_type == group_type:
        raise BridgeError("invalid_input", "user_type and group_type must differ")
    if not isinstance(existing_entities, list):
        raise BridgeError("invalid_input", "existing entities must be a list")
    if group_map is not None and not (isinstance(group_map, dict) and all(isinstance(k, str) and isinstance(v, str) and v for k, v in group_map.items())):
        raise BridgeError("invalid_input", "group_map must map a directory group to a group id")
    if attr_map is not None and not (isinstance(attr_map, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in attr_map.items())):
        raise BridgeError("invalid_input", "attr_map must map an entity attribute to a directory attribute path")

    # directory group id -> entity id (or absent when dropped)
    gid: dict = {}
    # What a group was identified BY when the caller did not name it by its directory id: two
    # different directory groups reaching one entity that way would be merged without anyone
    # having asked for it. Display names are not unique (Entra, Okta, SCIM), and a Keycloak
    # group name may imitate another group's path.
    by_label: dict = {}
    for g in snapshot.groups.values():
        if group_map is None:
            gid[g.id] = _ident("group", g, group_id)
            label = None if group_id == "id" else gid[g.id]
        elif g.id in group_map:
            gid[g.id] = group_map[g.id]      # named by its directory id: an explicit choice, merging included
            label = None
        elif g.name in group_map:
            gid[g.id] = group_map[g.name]
            label = g.name
        else:
            continue
        if label is not None:
            if label in by_label:
                raise BridgeError("duplicate_group", f"two different directory groups ({by_label[label]!r} and {g.id!r}) are both called {label!r} "
                                                     f"and would become the one group {gid[g.id]!r}. Nothing is merged by name: rename one of them, "
                                                     "or name each by its directory id in the group map (mapping both ids to one group merges them on purpose)")
            by_label[label] = g.id

    def kept_up(g: str, seen: frozenset = frozenset()) -> set:
        """The nearest kept groups at or above directory group `g`."""
        if g not in snapshot.groups:
            raise BridgeError("snapshot_inconsistent", f"a membership names group {g!r}, which the directory did not list")
        if g in gid:
            return {gid[g]}
        out: set = set()
        for p in snapshot.groups[g].parents:
            if p not in seen:
                out |= kept_up(p, seen | {g})
        return out

    group_parents: dict = {}
    for g in snapshot.groups.values():
        if g.id not in gid:
            continue
        ps = group_parents.setdefault(gid[g.id], set())
        for p in g.parents:
            ps |= kept_up(p, frozenset({g.id}))
    for e, ps in group_parents.items():
        ps.discard(e)

    users: dict = {}
    for u in snapshot.users.values():
        if not u.active:
            continue
        eid = _ident("user", u, user_id)
        if eid in users:
            raise BridgeError("duplicate_user", f"two directory users map to the entity id {eid!r}; choose another user_id")
        attrs = {}
        for target, source in (attr_map or {}).items():
            v = _path(u.attrs or {}, source)
            if v is None:
                continue
            if not _attr_ok(v):
                raise BridgeError("attr_invalid", f"user {eid!r}: attribute '{source}' is not a string, integer, boolean or list of strings")
            attrs[target] = v
        parents: set = set()
        for g in snapshot.memberships.get(u.id, ()):
            parents |= kept_up(g)
        users[eid] = (attrs, parents)

    ref = lambda t, ids: [{"type": t, "id": i} for i in sorted(ids)]
    out = [{"uid": {"type": group_type, "id": e}, "attrs": {}, "parents": ref(group_type, group_parents[e])} for e in sorted(group_parents)]
    out += [{"uid": {"type": user_type, "id": e}, "attrs": users[e][0], "parents": ref(group_type, users[e][1])} for e in sorted(users)]
    for e in existing_entities:
        try:
            uid = cedar.Store._uid(e.get("uid") if isinstance(e, dict) else None)
        except ValueError as err:
            raise BridgeError("entities_invalid", f"existing entities: {err}") from None
        if uid[0] not in (user_type, group_type):
            out.append(e)
    return out


def _effective(entities: list, user_type: str) -> dict:
    """user id -> sorted "Type::id" of every group the user is in, directly or through nesting."""
    try:
        store = cedar.Store(entities)
    except (ValueError, AttributeError, TypeError) as e:
        raise BridgeError("entities_invalid", f"not a valid entity list: {e}") from None
    return {uid[1]: sorted(f"{a[0]}::{a[1]}" for a in store.ancestors(uid)) for uid in store.attrs if uid[0] == user_type}


def diff(old: list, new: list, *, user_type: str = "User") -> dict:
    """What a sync would change, as sorted lists:
    {"users_added", "users_removed", "membership_changed": [{"user", "added", "removed"}]}.
    Membership is the effective one (through nested groups), written "Type::id"."""
    a, b = _effective(old, user_type), _effective(new, user_type)
    changed = []
    for u in sorted(set(a) & set(b)):
        if a[u] != b[u]:
            changed.append({"user": u, "added": sorted(set(b[u]) - set(a[u])), "removed": sorted(set(a[u]) - set(b[u]))})
    return {"users_added": sorted(set(b) - set(a)), "users_removed": sorted(set(a) - set(b)), "membership_changed": changed}


def users_to_revoke(d: dict) -> list:
    """The users of a `diff` whose live tokens should end: every user the sync
    removed, and every user who lost at least one group (their tokens may
    carry a role they no longer hold). Users who only gained groups are not listed."""
    return sorted(set(d.get("users_removed") or []) | {c["user"] for c in d.get("membership_changed") or [] if c.get("removed")})


def revoke_changed(backend, d: dict, by: str = "sync") -> dict:
    """Revoke-by-user for every user in `users_to_revoke(d)`.

    `backend` is an Engine or a DaemonClient (anything with `.call(op,
    payload)`); `d` is the "diff" of a `write_entities` / `sync` result.
    Call it AFTER the write succeeded. Returns {"revoked": [users]}.

    Guarantees: every listed user is attempted, even after a failure; if any
    call fails, BridgeError("revoke_failed") names exactly the users that were
    NOT revoked (`.detail` = {"revoked": [...], "not_revoked": [...]}), so the
    caller can retry them. Nothing is revoked for users whose membership did
    not shrink.

    What a revoke reaches: every token issued for that user up to now, sub-agent
    tokens included, in every engine sharing this state directory or served
    by this daemon. A verify-only engine elsewhere keeps honouring such a
    token until it expires; cloud credentials already handed out are not
    affected. A token issued AFTER the call is not revoked: issuance must
    already see the new membership (reload the engine before revoking)."""
    done, failed = [], []
    for user in users_to_revoke(d):
        try:
            r = backend.call("revoke", {"user": user, "by": by})
            ok = isinstance(r, dict) and r.get("ok") is True and r.get("revoked_user") == user
        except Exception:
            ok = False
        (done if ok else failed).append(user)
    if failed:
        raise BridgeError("revoke_failed", "the tokens of these users were NOT revoked: " + ", ".join(failed)
                          + (". Revoked: " + ", ".join(done) if done else ". None were revoked")
                          + ". Retry with `smartdelegate token revoke --user U`", {"revoked": done, "not_revoked": failed})
    return {"revoked": done}


def _atomic_write(path: Path, text: str, validate=None) -> None:
    """Write `text` to a temporary file beside `path`, run `validate(tmp)`,
    then move it into place. On any failure the temporary file is removed
    and `path` is untouched."""
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if validate:
            validate(Path(tmp))
        try:
            os.chmod(tmp, (os.stat(path).st_mode & 0o777) if path.exists() else 0o644)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _validate_entities(tmp: Path) -> None:
    try:
        loaded = json.loads(tmp.read_text(encoding="utf-8"))
        if not isinstance(loaded, list) or not all(isinstance(e, dict) for e in loaded):
            raise ValueError("expected a list of entities")
        cedar.Store(loaded)
    except (ValueError, TypeError, AttributeError, OSError) as e:
        raise BridgeError("entities_invalid", f"the new entities.json does not load, nothing was written: {e}") from None


def sidecar_path(path) -> Path:
    """entities.json -> entities.sync.json (same directory)."""
    p = Path(path)
    return p.with_name(p.stem + ".sync.json")


def write_entities(path, entities: list, *, source: str, force: bool = False, max_removal_fraction: float = 0.3,
                   dry_run: bool = False, user_type: str = "User", group_type: str = "Group",
                   now: datetime.datetime | None = None) -> dict:
    """Replace entities.json with `entities`, atomically and guardedly.

    Guarantees:
      * `path` is either the complete old file or the complete new file, never a mix: the new
        content is written to a temporary file in the same directory, loaded with
        `cedar.Store` (the loader the engine uses), then moved with os.replace;
      * unless `force`, BridgeError("removal_guard") and nothing written when more than
        `max_removal_fraction` of the existing users would disappear, or more than that fraction
        of the existing users who are in some group would be left in none;
      * with `dry_run`, nothing is written;
      * on success `entities.sync.json` is written beside it: {"source", "synced_at", "users",
        "groups", "sha256", ...}. It is not part of the bundle version.

    Returns {"written", "path", "diff", "users", "groups", "removal_fraction",
    "lost_membership_fraction", "sha256", "synced_at"}.

    entities.json is part of the bundle version: a signed bundle must be
    re-signed after a sync (an engine that requires a signature refuses the
    changed bundle until then), and a running engine needs `reload`."""
    path = Path(path)
    if not 0 <= max_removal_fraction <= 1:
        raise BridgeError("invalid_input", "max_removal_fraction must be between 0 and 1")
    old: list = []
    if path.exists():
        try:
            old = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(old, list):
                raise ValueError("expected a list")
        except (OSError, ValueError) as e:
            raise BridgeError("entities_unreadable", f"{path}: the existing file cannot be read, refusing to replace it blindly: {e}") from None
    d = diff(old, entities, user_type=user_type)
    before, after = _effective(old, user_type), _effective(entities, user_type)
    removal = len(d["users_removed"]) / len(before) if before else 0.0
    had = [u for u, g in before.items() if g]
    lost = [u for u in had if not after.get(u)]
    lost_fraction = len(lost) / len(had) if had else 0.0
    text = json.dumps(entities, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    stamp = (now or datetime.datetime.now(datetime.timezone.utc)).astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    groups = sum(1 for e in entities if isinstance(e, dict) and isinstance(e.get("uid"), dict) and e["uid"].get("type") == group_type)
    result = {"written": False, "path": str(path), "diff": d, "users": len(after), "groups": groups,
              "removal_fraction": round(removal, 4), "lost_membership_fraction": round(lost_fraction, 4),
              "sha256": digest, "synced_at": stamp, "source": source}
    if not force and (removal > max_removal_fraction or lost_fraction > max_removal_fraction):
        raise BridgeError("removal_guard",
                          f"this sync would remove {len(d['users_removed'])} of {len(before)} users and leave {len(lost)} of {len(had)} "
                          f"users without any group, more than the allowed fraction {max_removal_fraction}; nothing was written. "
                          "Check the directory response, then repeat with force if it is intended", result)
    if dry_run:
        return result
    try:
        _atomic_write(path, text, _validate_entities)
        side = {"source": source, "synced_at": stamp, "users": len(after), "groups": groups, "sha256": digest,
                "users_added": len(d["users_added"]), "users_removed": len(d["users_removed"]),
                "membership_changed": len(d["membership_changed"]), "forced": bool(force)}
        _atomic_write(sidecar_path(path), json.dumps(side, indent=2) + "\n")
    except OSError as e:
        raise BridgeError("write_failed", f"{path}: {e.strerror or e}") from None
    result["written"] = True
    return result


def sync(snapshot: Snapshot, path, *, source: str | None = None, force: bool = False, max_removal_fraction: float = 0.3,
         dry_run: bool = False, **mapping) -> dict:
    """Snapshot -> entities.json in one call: reads the existing file (for
    the entities to keep), runs `to_entities(**mapping)` and `write_entities`.
    Same guarantees and result as `write_entities`."""
    path = Path(path)
    existing: list = []
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as e:
            raise BridgeError("entities_unreadable", f"{path}: {e}") from None
    entities = to_entities(snapshot, existing, **mapping)
    return write_entities(path, entities, source=source or snapshot.source or "unknown", force=force,
                          max_removal_fraction=max_removal_fraction, dry_run=dry_run,
                          user_type=mapping.get("user_type", "User"), group_type=mapping.get("group_type", "Group"))
