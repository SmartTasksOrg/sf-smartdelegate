package smartdelegate

import "strings"

// RuleID is the Smart* family rule id of a decision reason or error code:
// "policy_forbid" -> "DELEGATE-POLICY-FORBID".
func RuleID(code string) string {
	return "DELEGATE-" + strings.ReplaceAll(strings.ToUpper(code), "_", "-")
}

// EngineError is a request that could not be processed. It becomes
// {"ok": false, "error": {"code", "message", "rule"}}; never an allow.
type EngineError struct {
	Code    string
	Message string
}

func (e *EngineError) Error() string { return e.Code + ": " + e.Message }

// Result is the JSON form of the error, as returned by Engine.Call.
func (e *EngineError) Result() map[string]any {
	return map[string]any{"ok": false, "error": map[string]any{"code": e.Code, "message": e.Message, "rule": RuleID(e.Code)}}
}

func newErr(code, message string) *EngineError { return &EngineError{Code: code, Message: message} }

// throw aborts the current operation with an engine error. Engine.Call and
// NewEngine recover it; nothing escapes to the caller as a panic.
func throw(code, message string) {
	panic(newErr(code, message))
}

// deny is a refusal that is a decision, not an error: it ends the decision
// steps and becomes {"effect": "deny", "reason": code}.
type deny struct {
	code, detail string
	claims       map[string]any
}
