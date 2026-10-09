"""Reference RoleCatalog: roles.json in a bundle directory, validated by the
engine's own loader and replaced atomically.

roles.json is part of the bundle version and of the bundle signature: after a
write, a signed bundle must be re-signed and a running engine must reload.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from sf_smartdelegate.bundle import Role
from sf_smartdelegate.errors import EngineError

from ..contracts import CatalogError


class FileRoleCatalog:
    def __init__(self, bundle_dir):
        self.path = Path(bundle_dir) / "roles.json"

    def load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            return {"roles": {}}
        except (OSError, ValueError) as e:
            raise CatalogError("roles_unreadable", str(e)) from None

    def validate(self, document: dict) -> None:
        if not isinstance(document, dict) or set(document) != {"roles"} or not isinstance(document["roles"], dict):
            raise CatalogError("roles_parse", 'expected {"roles": {...}} and nothing else at the top level')
        for name, spec in document["roles"].items():
            try:
                Role(name, spec)          # the loader the engine uses: unknown keys, types, the capability
            except EngineError as e:
                raise CatalogError("roles_parse", f"role '{name}': {e.message}") from None
            except Exception as e:
                raise CatalogError("roles_parse", str(e)) from None

    def write(self, document: dict) -> str:
        self.validate(document)
        text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
        fd, tmp = tempfile.mkstemp(prefix=".roles.", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise CatalogError("write_failed", str(e.strerror or e)) from None
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
