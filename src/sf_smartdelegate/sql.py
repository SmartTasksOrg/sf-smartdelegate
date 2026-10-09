"""SQL connector: turns a decision into a SELECT that only names permitted
columns and carries the row filter as bound parameters, then passes every
row it fetched through the decision's field mask before returning it.
Works with any DB-API connection; `paramstyle` is "qmark" (sqlite3) or
"format" (psycopg2 / psycopg: %s).

The mask is the control. Naming fewer columns is an optimisation: a column
that holds structured data (JSON/JSONB, an array of records) is one name in
SQL and many fields in the catalog, and only the mask can remove
`addresses[].geo` from an `addresses` the principal may otherwise read.

Two ways to make the decision (spec/API.md, "SQL connector"):

  one decision per query (default)
      `attrs` are the resource attributes the caller vouches for. The row
      filter of the decision goes into the WHERE clause.
  one decision per row (`row_attrs`, `id_column`)
      attributes (and the resource id) are read from each fetched row, the
      way a policy sees a single record: `row_attrs={"region": "region"}`.
      Rows the decision denies are dropped, the others are masked with their
      own decision. The database returns candidate rows first, so narrow
      the query with `where`.

The database credential lives with this connector, not with the agent."""
from __future__ import annotations

import json
import re

from . import fields
from .backend import Backend
from .guard import ApprovalRequired, Denied

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TOKEN_REASONS = ("token_invalid", "token_expired", "token_revoked")


def _quote(name: str) -> str:
    if not isinstance(name, str) or not _IDENT.match(name):
        raise ValueError(f"'{name}' is not a plain SQL identifier")
    return '"' + name + '"'


def _mask_of(decision: dict) -> fields.Mask:
    f = decision["obligations"]["fields"]
    status = {n: fields.ALLOW for n in f.get("allow") or []}
    status.update({n: fields.DENY for n in f.get("deny") or []})
    status.update({n: fields.REDACT for n in f.get("redact") or []})
    return fields.Mask(status)


def _mask_row(row: dict, mask: fields.Mask) -> dict:
    """The row as the principal may see it: the engine's own field walk
    (nested paths, `[]` paths, redaction). A column the catalog describes
    member by member whose value arrived as text is parsed as JSON first;
    text that is not JSON cannot be checked and is withheld."""
    row = dict(row)
    for col in list(row):
        if isinstance(row[col], (str, bytes)) and mask.has_children(col):
            try:
                row[col] = json.loads(row[col])
            except (ValueError, RecursionError):
                del row[col]
    return fields._walk_object(row, "", False, mask, set())


class SqlGuard:
    def __init__(self, backend: Backend, connection, paramstyle: str = "qmark"):
        if paramstyle not in ("qmark", "format"):
            raise ValueError("paramstyle must be 'qmark' or 'format'")
        self.backend = backend
        self.conn = connection
        self.mark = "?" if paramstyle == "qmark" else "%s"

    def _decide(self, token: str, resource: str, id, attrs) -> dict:
        d = self.backend.authorize(token, "read", resource, id, attrs=dict(attrs) if attrs else None)
        return d

    @staticmethod
    def _refuse(d: dict):
        raise ApprovalRequired(d) if d.get("reason") == "approval_required" else Denied(d)

    def build_select(self, token: str, table: str, resource: str, *, columns: list[str],
                     where: dict | None = None, limit: int | None = None, id: str | None = None,
                     attrs: dict | None = None) -> tuple[str, list, dict]:
        """Returns (sql, params, decision). `columns` are the table columns the
        caller wants; the ones the principal may not read are left out. Raises
        Denied when the call is not allowed or no requested column is permitted.
        Column names must equal the catalog's field names. `attrs` are the
        resource attributes the decision is made on (tenant, region, ...): the
        caller states them, so they must be true of every row the query can
        return (a per-tenant view, a `where` on the same value)."""
        d = self._decide(token, resource, id, attrs)
        if d.get("effect") != "allow":
            self._refuse(d)
        allowed = [f for f in d["obligations"]["fields"]["allow"] if _IDENT.match(f)]
        cols = [c for c in columns if c in allowed]
        if not cols:
            raise Denied({"reason": "field_denied", "detail": "none of the requested columns is permitted"})
        clauses, params = [], []
        # the policy's row filter always applies; caller conditions can only narrow further
        for c in d["obligations"].get("row_filter", []):
            clauses.append(f"{_quote(c['column'])} = {self.mark}")
            params.append(c["value"])
        for col, val in (where or {}).items():
            if col not in allowed:
                # filtering on a hidden column would leak it one bit at a time
                raise Denied({"reason": "field_denied", "detail": f"cannot filter on '{col}'"})
            clauses.append(f"{_quote(col)} = {self.mark}")
            params.append(val)
        sql = f"SELECT {', '.join(_quote(c) for c in cols)} FROM {_quote(table)}"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        return sql, params, d

    def _fetch(self, sql: str, params: list) -> list[dict]:
        cur = self.conn.cursor()
        cur.execute(sql, params)
        names = [c[0] for c in cur.description]
        return [dict(zip(names, row)) for row in cur.fetchall()]

    def select(self, token: str, table: str, resource: str, *, columns: list[str], where: dict | None = None,
               limit: int | None = None, id: str | None = None, attrs: dict | None = None,
               row_attrs: dict | None = None, id_column: str | None = None) -> list[dict]:
        if row_attrs or id_column:
            return self._select_per_row(token, table, resource, columns, where, limit, attrs, row_attrs or {}, id_column)
        sql, params, d = self.build_select(token, table, resource, columns=columns, where=where, limit=limit, id=id, attrs=attrs)
        mask = _mask_of(d)
        return [_mask_row(r, mask) for r in self._fetch(sql, params)]

    def _select_per_row(self, token, table, resource, columns, where, limit, attrs, row_attrs: dict, id_column) -> list[dict]:
        """Fetch candidate rows, decide each on its own attributes, mask each with its own decision."""
        wanted = list(dict.fromkeys(columns))
        internal = [c for c in dict.fromkeys([*row_attrs.values(), *([id_column] if id_column else []), *(where or {})]) if c not in wanted]
        clauses, params = [], []
        for col, val in (where or {}).items():
            clauses.append(f"{_quote(col)} = {self.mark}")
            params.append(val)
        sql = f"SELECT {', '.join(_quote(c) for c in wanted + internal)} FROM {_quote(table)}"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        out, decisions = [], {}
        for row in self._fetch(sql, params):
            rid = row.get(id_column) if id_column else None
            rid = rid if isinstance(rid, str) else None
            values = {a: row.get(c) for a, c in row_attrs.items()}
            if any(isinstance(v, float) or not isinstance(v, (str, int, bool)) for v in values.values()):
                continue    # no usable attribute value: nothing can authorise this row
            key = (rid, json.dumps(values, sort_keys=True))
            if key not in decisions:
                d = self._decide(token, resource, rid, {**(attrs or {}), **values})
                if d.get("effect") != "allow" and d.get("reason") in _TOKEN_REASONS:
                    self._refuse(d)     # not about this row: the token itself is refused
                decisions[key] = d
            d = decisions[key]
            if d.get("effect") != "allow":
                continue
            ob = d["obligations"]
            allowed = set(ob["fields"]["allow"])
            # a condition on a column this principal may not read must not decide what it gets
            if any(col not in allowed for col in (where or {})):
                continue
            # the policy's row filter, on the row itself; a filter column that was not fetched cannot be checked
            if not fields._row_matches(row, ob.get("row_filter", [])):
                continue
            masked = _mask_row({c: row[c] for c in wanted if c in row}, _mask_of(d))
            if masked:
                out.append(masked)
        return out
