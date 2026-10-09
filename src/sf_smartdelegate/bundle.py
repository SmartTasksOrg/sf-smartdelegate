"""Policy bundle: compiled policies, entity store, field catalog, signature.

    bundle/
      policies.json     Cedar's JSON policy form, keyed by policy id. This is
                        what the engine evaluates.
      policies/*.cedar  the human-written source policies.json is compiled from
                        (`smartdelegate bundle compile`, in the Rust port)
      entities.json     users, groups, agents
      catalog.json      resources, fields, classification labels
      roles.json        roles a human can act in: who holds them and the most
                        an agent may be handed under each (optional)
      tests/*.json      policy unit tests (not part of the version)
      bundle.sig.json   file hashes + Ed25519 signature
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import cedar
from .canon import canon, sha256_hex
from .errors import EngineError


def _read(path: Path) -> str:
    try:
        with open(path, encoding="utf-8", newline="") as f:
            return f.read()
    except OSError as e:
        raise EngineError("bundle_io", f"{path}: {e.strerror or e}") from None
    except UnicodeDecodeError:
        raise EngineError("bundle_io", f"{path}: not UTF-8") from None


def manifest(dir: Path) -> dict[str, str]:
    """Relative path -> sha256 for every file that defines behaviour. Line
    endings are normalised so a Windows checkout has the same version."""
    files = {}
    digest = lambda p: sha256_hex(_read(p).replace("\r\n", "\n").encode("utf-8"))
    if (dir / "policies.json").exists():
        files["policies.json"] = digest(dir / "policies.json")
    else:
        raise EngineError("bundle_io", f"{dir / 'policies.json'}: missing. This port loads compiled policies; run `smartdelegate bundle compile` (Rust port) on the .cedar sources")
    for name in ("entities.json", "catalog.json", "roles.json"):
        if (dir / name).exists():
            files[name] = digest(dir / name)
    return files


def version_of(files: dict[str, str]) -> str:
    return sha256_hex(canon(files).encode("utf-8"))


# ---- keys ------------------------------------------------------------------
# Private keys are base64 of the PKCS#8 DER encoding; public keys are base64 of
# the 32 raw bytes. The key id is the first 16 hex characters of sha256(public).

def keygen() -> tuple[str, str]:
    k = Ed25519PrivateKey.generate()
    der = k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return base64.b64encode(der).decode(), base64.b64encode(public_raw(k)).decode()


def public_raw(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_private(b64: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_der_private_key(base64.b64decode(b64.strip(), validate=True), password=None)
    except Exception:
        raise EngineError("crypto", "private key is not base64 Ed25519 PKCS#8") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise EngineError("crypto", "private key is not Ed25519")
    return key


def load_public(b64: str) -> tuple[Ed25519PublicKey, bytes]:
    try:
        raw = base64.b64decode(b64.strip(), validate=True)
        return Ed25519PublicKey.from_public_bytes(raw), raw
    except Exception:
        raise EngineError("crypto", "public key is not base64 of 32 raw Ed25519 bytes") from None


def key_id(public_b64: str) -> str:
    return sha256_hex(load_public(public_b64)[1])[:16]


def sign(dir: Path, private_b64: str) -> dict:
    key = load_private(private_b64)
    files = manifest(dir)
    version = version_of(files)
    public = base64.b64encode(public_raw(key)).decode()
    payload = {"files": files, "version": version}
    out = {"files": files, "version": version, "key_id": key_id(public), "alg": "Ed25519",
           "signature": base64.b64encode(key.sign(canon(payload).encode("utf-8"))).decode()}
    (dir / "bundle.sig.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return out


def _verify_signature(dir: Path, files: dict, public_b64: str) -> None:
    p = dir / "bundle.sig.json"
    if not p.exists():
        raise EngineError("bundle_unsigned", "a signed bundle is required, but bundle.sig.json is missing")
    try:
        sig = json.loads(_read(p))
        raw_sig = base64.b64decode(sig.get("signature", ""), validate=True)
    except Exception:
        raise EngineError("bundle_signature", "bundle.sig.json is malformed") from None
    payload = {"files": sig.get("files"), "version": sig.get("version")}
    try:
        load_public(public_b64)[0].verify(raw_sig, canon(payload).encode("utf-8"))
    except InvalidSignature:
        raise EngineError("bundle_signature", "bundle signature does not verify with the configured key") from None
    if files != sig.get("files"):
        raise EngineError("bundle_signature", "bundle files changed after signing")


class Bundle:
    def __init__(self, dir, public_key: str | None = None):
        """`public_key`: when set, the bundle must carry a valid signature by
        that key or loading fails."""
        self.dir = Path(dir)
        files = manifest(self.dir)
        self.version = version_of(files)
        self.signed_by = None
        if public_key:
            _verify_signature(self.dir, files, public_key)
            self.signed_by = key_id(public_key)

        try:
            doc = json.loads(_read(self.dir / "policies.json"))
            compiled = doc["policies"]
            assert isinstance(compiled, dict)
        except EngineError:
            raise
        except Exception as e:
            raise EngineError("policy_parse", f"policies.json: {e}") from None
        # policies.json records the hash of each .cedar file it was compiled
        # from. This port cannot parse Cedar text, but it can tell when a
        # source was edited (or added) without recompiling, so the policy a
        # reviewer reads is the policy that runs.
        sources = doc.get("sources") if isinstance(doc.get("sources"), dict) else {}
        on_disk = {f"policies/{p.name}": sha256_hex(_read(p).replace("\r\n", "\n").encode("utf-8"))
                   for p in sorted((self.dir / "policies").glob("*.cedar"))} if (self.dir / "policies").is_dir() else {}
        if on_disk and on_disk != sources:
            changed = sorted(k for k in set(on_disk) | set(sources) if on_disk.get(k) != sources.get(k))
            raise EngineError("bundle_stale", "policies.json does not match the .cedar sources (" + ", ".join(changed)
                              + "); run `smartdelegate bundle compile` from the Rust port")
        self.policies: dict[str, cedar.Policy] = {}
        for pid, est in compiled.items():
            try:
                self.policies[pid] = cedar.Policy(pid, est)
            except cedar.Unsupported as e:
                raise EngineError("policy_parse", f"policies.json: {pid}: {e}") from None

        self.entities_json: list = []
        #: "Type::id" -> attrs exactly as written in entities.json
        self.attrs: dict = {}
        if (self.dir / "entities.json").exists():
            try:
                self.entities_json = json.loads(_read(self.dir / "entities.json"))
                if not isinstance(self.entities_json, list) or not all(isinstance(e, dict) for e in self.entities_json):
                    raise ValueError("expected a list of entities")
                self.store = cedar.Store(self.entities_json)
                for e in self.entities_json:
                    uid = cedar.Store._uid(e.get("uid"))
                    self.attrs[f"{uid[0]}::{uid[1]}"] = e.get("attrs") or {}
            except EngineError:
                raise
            except Exception as e:
                raise EngineError("entities_parse", f"entities.json: {e}") from None
        else:
            self.store = cedar.Store()

        self.catalog: dict[str, dict] = {}
        if (self.dir / "catalog.json").exists():
            try:
                cat = json.loads(_read(self.dir / "catalog.json"))
                for path, rdef in (cat.get("resources") or {}).items():
                    if not cedar.valid_type(rdef.get("entity_type")):
                        raise ValueError(f"{path}: entity_type is missing or malformed")
                    fields = {}
                    for name, fdef in (rdef.get("fields") or {}).items():
                        mask = fdef.get("mask")
                        if mask not in (None, "drop", "redact"):
                            raise ValueError(f"{path}.{name}: mask must be 'drop' or 'redact'")
                        fields[name] = {"labels": list(fdef.get("labels") or []), "mask": mask}
                    self.catalog[path] = {"entity_type": rdef["entity_type"], "fields": fields}
            except (ValueError, TypeError, AttributeError) as e:
                raise EngineError("catalog_parse", str(e)) from None

        #: role name -> Role
        self.roles: dict[str, Role] = {}
        if (self.dir / "roles.json").exists():
            try:
                doc = json.loads(_read(self.dir / "roles.json"))
                assert isinstance(doc, dict) and isinstance(doc.get("roles"), dict), "expected {\"roles\": {...}}"
                for name, rdef in doc["roles"].items():
                    self.roles[name] = Role(name, rdef)
            except EngineError as e:
                raise EngineError("roles_parse", f"roles.json: {e.message}") from None
            except Exception as e:
                raise EngineError("roles_parse", f"roles.json: {e}") from None


_ROLE_KEYS = {"description", "members", "cap", "max_ttl", "tasks", "agents", "bindings"}


def _pattern_list(v, what: str) -> list:
    if not isinstance(v, list) or not v or not all(isinstance(x, str) and x and "*" not in x[:-1] for x in v):
        raise ValueError(f"{what} must be a non-empty list of names, each with at most one trailing *")
    return list(v)


class Role:
    """A role a human holds and can lend to an agent for one task.

    members   entities whose members hold the role (the user itself, or any
              group the user is in)
    cap       the ceiling: the most a token issued under this role can carry
    max_ttl   tokens under this role live at most this many seconds
    tasks     when set, the token must name a task matching one pattern
    agents    when set, only these agents may be started in this role
    bindings  free-form, for bridges (cloud role ARNs and the like); ignored
              by the engine"""

    def __init__(self, name: str, v):
        from .tokens import Cap
        if not name or not isinstance(v, dict):
            raise ValueError(f"role '{name}' must be an object")
        unknown = set(v) - _ROLE_KEYS
        if unknown:
            # a misspelt key must not silently loosen a role
            raise ValueError(f"role '{name}': unknown field(s): {', '.join(sorted(unknown))}")
        self.name = name
        members = v.get("members")
        if not isinstance(members, list) or not members:
            raise ValueError(f"role '{name}': members must be a non-empty list of {{type, id}}")
        self.members = []
        for m in members:
            if not isinstance(m, dict) or not cedar.valid_type(m.get("type")) or not isinstance(m.get("id"), str):
                raise ValueError(f"role '{name}': each member must be {{type, id}}")
            self.members.append(cedar.Entity(m["type"], m["id"]))
        if "cap" not in v:
            raise ValueError(f"role '{name}': cap is required")
        self.cap = Cap.from_json(v["cap"])
        self.cap.validate()
        self.max_ttl = None
        if "max_ttl" in v:
            t = v["max_ttl"]
            if not isinstance(t, int) or isinstance(t, bool) or t <= 0:
                raise ValueError(f"role '{name}': max_ttl must be a positive integer")
            self.max_ttl = t
        self.tasks = _pattern_list(v["tasks"], f"role '{name}': tasks") if "tasks" in v else None
        self.agents = _pattern_list(v["agents"], f"role '{name}': agents") if "agents" in v else None
        if "bindings" in v and not isinstance(v["bindings"], dict):
            raise ValueError(f"role '{name}': bindings must be an object")
        self.bindings = v.get("bindings") or {}
