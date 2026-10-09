from __future__ import annotations


def rule_id(code: str) -> str:
    """The Smart* family rule id of a decision reason or error code:
    `policy_forbid` -> `DELEGATE-POLICY-FORBID`."""
    return "DELEGATE-" + code.upper().replace("_", "-")


class EngineError(Exception):
    """A request that could not be processed. Becomes
    {"ok": false, "error": {"code", "message"}}; never an allow."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message

    def to_json(self) -> dict:
        return {"ok": False, "error": {"code": self.code, "message": self.message, "rule": rule_id(self.code)}}
