package smartdelegate

// One test per bullet of "Strictness (0.3)" in spec/PORTING.md. Where the
// Python reference is available the same input is also given to it.

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Audit lines end at "\n" and nowhere else.
func TestStrictAuditLinesEndAtNewlineOnly(t *testing.T) {
	e, state := newTestEngine(t, nil)
	other, err := NewEngine(ConformanceConfig(specBundle(t), state, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	// U+2028, U+2029, U+0085, FS/GS/RS, VT and FF inside recorded strings
	odd := "a\u2028b\u2029c\u0085d\x1ce\x1df\x1eg\vh\fi"
	for i, eng := range []*Engine{e, other, e, other} {
		// each engine chains onto a record the other one wrote: the resync must read it whole
		r := eng.Call("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap(), "task": odd, "tenant": odd, "now": testNow})
		if r["ok"] != true {
			t.Fatalf("call %d after a record with line-separator characters: %s", i, Canon(r))
		}
	}
	tail := e.Call("audit_tail", map[string]any{"n": 10})
	records, _ := tail["records"].([]any)
	if len(records) != 4 {
		t.Fatalf("audit_tail must return all 4 records, got %d: %s", len(records), Canon(tail))
	}
	for _, rec := range records {
		if m := rec.(map[string]any); m["task"] != odd || m["tenant"] != odd {
			t.Errorf("a record was cut or changed: %s", Canon(rec))
		}
	}
	if v := other.Call("audit_verify", map[string]any{}); v["records"] != int64(4) {
		t.Errorf("audit_verify: %s", Canon(v))
	}
	raw, _ := os.ReadFile(filepath.Join(state, "audit.jsonl"))
	if n := strings.Count(string(raw), "\n"); n != 4 || !strings.Contains(string(raw), "\u2028") {
		t.Errorf("the log must hold 4 lines with U+2028 written as itself; %d newlines", n)
	}
	// a carriage return before the newline is whitespace, not a second line
	crlf := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(crlf, []byte(strings.ReplaceAll(string(raw), "\n", "\r\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, _, err := VerifyAudit(crlf); err != nil || n != 4 {
		t.Errorf("a log with CRLF line ends: %d %v", n, err)
	}
	if havePython(t) {
		cfg := pyConfig(t, "c.json", map[string]any{"bundle_dir": specBundle(t), "state_dir": state})
		theirs := pythonCall(t, cfg, "audit_tail", map[string]any{"n": 10})
		if Canon(theirs["records"]) != Canon(tail["records"]) {
			t.Errorf("audit_tail differs from the reference:\n  go        %s\n  reference %s", Canon(tail["records"]), Canon(theirs["records"]))
		}
		// the reference chains onto the Go records, and the Go engine onto the reference's
		if r := pythonCall(t, cfg, "revoke", map[string]any{"token_id": odd}); r["ok"] != true {
			t.Errorf("the reference could not append after the Go port's records: %s", Canon(r))
		}
		if r := e.Call("revoke", map[string]any{"token_id": odd + "2"}); r["ok"] != true {
			t.Errorf("the Go port could not append after the reference's record: %s", Canon(r))
		}
		if v := python(t, "audit", "verify", "--config", cfg); v.code != 0 || v.json(t)["records"] != int64(6) {
			t.Errorf("reference audit verify: %s %s", v.stdout, v.stderr)
		}
	}
}

// base64url is strict: one token has one spelling.
func TestStrictBase64URL(t *testing.T) {
	for _, bad := range []string{"", "A", "AAAAA", "AA=", "AA==", "AAA=", "AA A", "AA\n", "AA+A", "AA/A", "AA!A", "AAAA!!!!", "AA.A", "\u00e9\u00e9", "AA\x00A", " AAA", "AAA~"} {
		if got, err := b64uDec(bad); err == nil {
			t.Errorf("b64uDec(%q) = %v, want an error", bad, got)
		}
	}
	for good, want := range map[string]string{"AA": "\x00", "AAA": "\x00\x00", "AAAA": "\x00\x00\x00", "-_-_": "\xfb\xff\xbf", "aGk": "hi", "AB": "\x00"} {
		if got, err := b64uDec(good); err != nil || string(got) != want {
			t.Errorf("b64uDec(%q) = %q, %v", good, got, err)
		}
	}
	e, _ := newTestEngine(t, nil)
	token := issue(t, e, nil)["token"].(string)
	parts := strings.Split(token, ".")
	spellings := map[string]string{
		"junk after the signature":        token + "!!!!",
		"junk inside the signature":       parts[0] + "." + parts[1] + "." + parts[2][:5] + "~~~~" + parts[2][5:],
		"junk inside the payload":         parts[0] + "." + parts[1][:8] + "$$$$" + parts[1][8:] + "." + parts[2],
		"junk inside the header":          parts[0][:4] + "****" + parts[0][4:] + "." + parts[1] + "." + parts[2],
		"padded signature":                token + "==",
		"padded payload":                  parts[0] + "." + parts[1] + "==." + parts[2],
		"standard alphabet":               strings.NewReplacer("-", "+", "_", "/").Replace(token) + "+/+/",
		"whitespace":                      token + "\n",
		"a space in the header":           parts[0][:4] + " " + parts[0][4:] + "." + parts[1] + "." + parts[2],
		"non-ASCII":                       token + "\u00e9\u00e9",
		"one extra character":             token + "A",
		"an empty signature":              parts[0] + "." + parts[1] + ".",
		"an empty header":                 "." + parts[1] + "." + parts[2],
		"four parts":                      token + ".AAAA",
		"signature with a line separator": parts[0] + "." + parts[1] + "." + parts[2] + "\u2028",
	}
	for name, tok := range spellings {
		if tok == token {
			continue
		}
		for op, in := range map[string]map[string]any{
			"authorize": readRequest(tok), "inspect_token": {"token": tok, "now": testNow},
			"exchange_token": {"subject_token": tok, "actor": "refund-helper", "now": testNow}, "revoke": {"token": tok, "now": testNow},
		} {
			r := e.Call(op, in)
			reason, _ := r["reason"].(string)
			if reason == "" {
				reason = errCode(r)
			}
			if reason != "token_invalid" {
				t.Errorf("%s, %s: got %s, want token_invalid", name, op, Canon(r))
			}
		}
	}
	if r := e.Call("authorize", readRequest(token)); r["effect"] != "allow" {
		t.Errorf("the one spelling must still work: %s", Canon(r))
	}
	// the same for the three parts of an ID token
	if _, err := verifyIDToken("AA!A.AAAA.AAAA", map[string]any{}, "i", "a", 0); err == nil || err.Code != "id_token_invalid" {
		t.Errorf("an ID token with a character outside the alphabet: %v", err)
	}
}

// Entity type names match in full.
func TestStrictEntityTypeNames(t *testing.T) {
	for _, good := range []string{"User", "_x", "A::B", "NS::Sub::T_1", "a1"} {
		if !validType(good) {
			t.Errorf("%q is a type name", good)
		}
	}
	for _, bad := range []any{"User\n", "\nUser", "User\r\n", "User ", " User", "", "1User", "A::", "::A", "A:B", "A::1B", "A::B\n", "A B", "A-B", "\u00c9", 5, nil, []any{"User"}} {
		if validType(bad) {
			t.Errorf("%q is not a type name", bad)
		}
	}
	if _, err := fromJSON(mustParse(t, `{"__entity": {"type": "User\n", "id": "u"}}`)); err == nil {
		t.Error("an entity reference whose type ends in a newline is not a Cedar value")
	}
	if _, err := NewStore(mustParse(t, `[{"uid": {"type": "User\n", "id": "u"}}]`).([]any)); err == nil {
		t.Error("an entity whose type ends in a newline must be refused")
	}
	e, _ := newTestEngine(t, map[string]any{"trust_caller_chain": true})
	token := issue(t, e, nil)["token"]
	req := readRequest(token)
	req["context"] = mustParse(t, `{"who": {"__entity": {"type": "User\n", "id": "alice"}}}`)
	if r := e.Call("authorize", req); errCode(r) != "invalid_context" {
		t.Errorf("context with a type ending in a newline: %s", Canon(r))
	}
	if r := e.Call("issue_token", map[string]any{"user": "dave", "agent": "support-bot", "cap": fullCap(), "now": testNow,
		"groups": []any{map[string]any{"type": "Group\n", "id": "support"}}}); errCode(r) != "delegation_denied" {
		t.Errorf("a group whose type ends in a newline is not a known group: %s", Canon(r))
	}
	if _, err := NewEngine(map[string]any{"bundle_dir": specBundle(t), "idp": map[string]any{"jwks": map[string]any{}, "issuer": "i", "audience": "a", "group_type": "Group\n"}}); err == nil || err.(*EngineError).Code != "invalid_config" {
		t.Errorf("idp.group_type ending in a newline: %v", err)
	}
}

// containsAll / containsAny check both operands are sets before looking at their contents.
func TestStrictContainsOperandsAreSets(t *testing.T) {
	store, _ := NewStore(nil)
	eval := func(op, left, right string) (any, error) {
		return evaluate(mustParse(t, fmt.Sprintf(`{%q: {"left": {"Value": %s}, "right": {"Value": %s}}}`, op, left, right)), &Env{Context: map[string]any{}, Store: store})
	}
	for _, op := range []string{"containsAll", "containsAny"} {
		for _, c := range [][2]string{{`"s"`, `[]`}, {`[]`, `"s"`}, {`1`, `[]`}, {`[]`, `1`}, {`{"a": 1}`, `[]`}, {`[]`, `{"a": 1}`}, {`true`, `[]`}, {`[]`, `false`},
			{`[1]`, `1`}, {`1`, `[1]`}, {`"s"`, `"s"`}, {`{"__entity": {"type": "T", "id": "x"}}`, `[]`}, {`[]`, `{"__entity": {"type": "T", "id": "x"}}`}} {
			if got, err := eval(op, c[0], c[1]); err == nil {
				t.Errorf("%s.%s(%s) = %v, want an error", c[0], op, c[1], got)
			}
		}
	}
	for _, c := range []struct {
		op, left, right string
		want            bool
	}{{"containsAll", `[]`, `[]`, true}, {"containsAny", `[]`, `[]`, false}, {"containsAll", `[1, 2]`, `[]`, true}, {"containsAny", `[1, 2]`, `[]`, false},
		{"containsAll", `[]`, `[1]`, false}, {"containsAll", `[1, "a", [2]]`, `[[2], 1, 1]`, true}, {"containsAny", `[1, 2]`, `[3, 2]`, true}, {"containsAny", `[1]`, `[true]`, false}} {
		if got, err := eval(c.op, c.left, c.right); err != nil || got != c.want {
			t.Errorf("%s.%s(%s) = %v (%v), want %v", c.left, c.op, c.right, got, err, c.want)
		}
	}
	// and the four eval cases that record the real Cedar engine's answer
	rep, err := RunEvalCases(filepath.Join(repoRoot(t), "spec", "conformance", "eval", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, r := range rep.Results {
		if strings.Contains(r.Name, "containsAll") || strings.Contains(r.Name, "containsAny") {
			found++
			if !r.Passed {
				t.Errorf("%s: %v", r.Name, r.Failures)
			}
		}
	}
	if found < 4 {
		t.Errorf("expected the containsAll / containsAny eval cases, found %d", found)
	}
}

// Policy JSON shapes are checked at load.
func TestStrictPolicyShapes(t *testing.T) {
	base := func(change string) string {
		p := map[string]any{"effect": "permit", "principal": scopeAll, "action": scopeAll, "resource": scopeAll}
		for k, v := range mustParse(t, change).(map[string]any) {
			p[k] = v
		}
		return Canon(p)
	}
	when := func(body string) string { return base(`{"conditions": [{"kind": "when", "body": ` + body + `}]}`) }
	bad := map[string]string{
		"conditions an empty object":       base(`{"conditions": {}}`),
		"conditions an empty string":       base(`{"conditions": ""}`),
		"conditions an object":             base(`{"conditions": {"kind": "when", "body": {"Value": true}}}`),
		"conditions null":                  base(`{"conditions": null}`),
		"conditions a number":              base(`{"conditions": 0}`),
		"annotations a list":               base(`{"annotations": ["id"]}`),
		"annotations a string":             base(`{"annotations": "id"}`),
		"annotations a number":             base(`{"annotations": 5}`),
		"annotations true":                 base(`{"annotations": true}`),
		"Set an empty object":              when(`{"Set": {}}`),
		"Set an empty string":              when(`{"Set": ""}`),
		"Set an object":                    when(`{"Set": {"a": {"Value": 1}}}`),
		"Set null":                         when(`{"Set": null}`),
		"Record an empty list":             when(`{"Record": []}`),
		"Record an empty string":           when(`{"Record": ""}`),
		"Record a list":                    when(`{"Record": [{"Value": 1}]}`),
		"Record null":                      when(`{"Record": null}`),
		"like pattern an empty object":     when(`{"like": {"left": {"Value": ""}, "pattern": {}}}`),
		"like pattern an empty string":     when(`{"like": {"left": {"Value": ""}, "pattern": ""}}`),
		"like pattern a string":            when(`{"like": {"left": {"Value": ""}, "pattern": "Wildcard"}}`),
		"like pattern null":                when(`{"like": {"left": {"Value": ""}, "pattern": null}}`),
		"like without a pattern":           when(`{"like": {"left": {"Value": ""}}}`),
		"scope entities an empty object":   base(`{"action": {"op": "in", "entities": {}}}`),
		"scope entities an empty string":   base(`{"action": {"op": "in", "entities": ""}}`),
		"scope entities an object":         base(`{"action": {"op": "in", "entities": {"type": "Action", "id": "read"}}}`),
		"scope entities null":              base(`{"action": {"op": "in", "entities": null}}`),
		"scope type with a newline":        base(`{"resource": {"op": "is", "entity_type": "Doc\n"}}`),
		"is: type with a trailing newline": when(`{"is": {"left": {"Var": "principal"}, "entity_type": "User\n"}}`),
	}
	good := map[string]string{
		"no conditions key":          base(`{}`),
		"conditions an empty list":   base(`{"conditions": []}`),
		"no annotations":             base(`{}`),
		"annotations null":           base(`{"annotations": null}`),
		"annotations empty":          base(`{"annotations": {}}`),
		"annotations with a null":    base(`{"annotations": {"id": null}}`),
		"Set empty":                  when(`{"Set": []}`),
		"Record empty":               when(`{"Record": {}}`),
		"like empty pattern":         when(`{"like": {"left": {"Value": ""}, "pattern": []}}`),
		"scope entities empty list":  base(`{"action": {"op": "in", "entities": []}}`),
		"scope entities a list of 2": base(`{"action": {"op": "in", "entities": [{"type": "Action", "id": "a"}, {"type": "Action", "id": "b"}]}}`),
	}
	for name, text := range bad {
		if _, err := NewPolicy("p", mustParse(t, text)); err == nil {
			t.Errorf("%s: loaded, want it refused", name)
		} else if _, ok := err.(*Unsupported); !ok {
			t.Errorf("%s: %T", name, err)
		}
		// through a bundle it is policy_parse
		dir := t.TempDir()
		writeBundle(t, dir, map[string]any{"policies.json": `{"policies": {"p": ` + text + `}}`})
		if _, err := NewEngine(map[string]any{"bundle_dir": dir}); err == nil || err.(*EngineError).Code != "policy_parse" {
			t.Errorf("%s: NewEngine: %v, want policy_parse", name, err)
		}
	}
	for name, text := range good {
		if _, err := NewPolicy("p", mustParse(t, text)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Token claims: `anc` is an array of strings.
func TestStrictTokenClaimAnc(t *testing.T) {
	private, _, _ := Keygen()
	keys, kerr := newKeyring(private, nil)
	if kerr != nil {
		t.Fatal(kerr)
	}
	e, err := NewEngine(map[string]any{"bundle_dir": specBundle(t), "signing_key": private, "allow_test_clock": true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	sign := func(anc any, drop bool) string {
		claims := map[string]any{"iss": "smartdelegate://local", "aud": "smartdelegate", "sub": "user:alice", "iat": testNow, "exp": testNow + 600, "jti": "t-1",
			"act": map[string]any{"sub": "agent:support-bot"}, "cap": fullCap(), "anc": anc}
		if drop {
			delete(claims, "anc")
		}
		head := b64u([]byte(`{"typ":"JWT","alg":"EdDSA","kid":"` + keys.kid + `"}`))
		body := b64u(MarshalJSON(claims))
		return head + "." + body + "." + b64u(ed25519.Sign(keys.private, []byte(head+"."+body)))
	}
	for name, anc := range map[string]any{"a string": "abc", "an empty string": "", "an object": map[string]any{"a": "b"}, "an empty object": map[string]any{}, "null": nil,
		"a number": 5, "true": true, "a list with a number": []any{"a", 5}, "a list with null": []any{nil}, "a list with a list": []any{[]any{"a"}}} {
		for op, in := range map[string]map[string]any{"authorize": readRequest(sign(anc, false)), "inspect_token": {"token": sign(anc, false), "now": testNow},
			"exchange_token": {"subject_token": sign(anc, false), "actor": "refund-helper", "now": testNow}, "revoke": {"token": sign(anc, false)}} {
			r := e.Call(op, in)
			reason, _ := r["reason"].(string)
			if reason == "" {
				reason = errCode(r)
			}
			if reason != "token_invalid" {
				t.Errorf("anc %s, %s: got %s, want token_invalid", name, op, Canon(r))
			}
		}
	}
	for name, token := range map[string]string{"absent": sign(nil, true), "empty": sign([]any{}, false), "two ids": sign([]any{"a", "b"}, false)} {
		r := e.Call("inspect_token", map[string]any{"token": token, "now": testNow})
		if r["valid"] != true {
			t.Errorf("anc %s: %s", name, Canon(r))
		}
	}
	// a revoked ancestor named in a well-formed anc still revokes
	mustOK(t, e.Call("revoke", map[string]any{"token_id": "b", "now": testNow}))
	if r := e.Call("authorize", readRequest(sign([]any{"a", "b"}, false))); r["reason"] != "token_revoked" {
		t.Errorf("a revoked ancestor: %s", Canon(r))
	}
}

// Files that are not UTF-8, and entities.json that is not a list of objects.
func TestStrictFilesThatAreNotUTF8(t *testing.T) {
	notUTF8 := []byte("{\"x\": \"\xff\xfe\xc3\x28\"}\n")

	// state.json -> state_io, at start and while running
	e, state := newTestEngine(t, nil)
	token := issue(t, e, nil)["token"]
	if err := os.WriteFile(filepath.Join(state, "state.json"), notUTF8, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"authorize", "info", "approvals", "issue_token"} {
		if r := e.Call(op, readRequest(token)); errCode(r) != "state_io" {
			t.Errorf("%s with a state.json that is not UTF-8: %s", op, Canon(r))
		}
	}
	if _, err := NewEngine(ConformanceConfig(specBundle(t), state, nil)); err == nil || err.(*EngineError).Code != "state_io" {
		t.Errorf("NewEngine with a state.json that is not UTF-8: %v", err)
	}
	if err := os.Remove(filepath.Join(state, "state.json")); err != nil {
		t.Fatal(err)
	}

	// the audit log -> audit_broken
	log := filepath.Join(state, "audit.jsonl")
	original, _ := os.ReadFile(log)
	if err := os.WriteFile(log, append(append([]byte{}, original...), notUTF8...), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.Call("audit_verify", map[string]any{}); errCode(r) != "audit_broken" {
		t.Errorf("audit_verify on a log that is not UTF-8: %s", Canon(r))
	}
	if _, _, err := VerifyAudit(log); err == nil || err.(*EngineError).Code != "audit_broken" {
		t.Errorf("VerifyAudit on a log that is not UTF-8: %v", err)
	}
	if _, err := NewEngine(ConformanceConfig(specBundle(t), state, nil)); err == nil || err.(*EngineError).Code != "audit_broken" {
		t.Errorf("NewEngine on a log that is not UTF-8: %v", err)
	}
	// audit_tail reads what it can; the decision that cannot be chained is refused
	if r := e.Call("audit_tail", map[string]any{"n": 5}); r["ok"] != true || len(r["records"].([]any)) != 2 {
		t.Errorf("audit_tail on a log whose last line is not UTF-8: %s", Canon(r))
	}
	if r := e.Call("authorize", readRequest(token)); errCode(r) != "audit_io" {
		t.Errorf("a decision after a record that is not UTF-8: %s", Canon(r))
	}
	var refState string
	if havePython(t) {
		// the same three files in a directory of the reference
		refState = filepath.Join(t.TempDir(), "state")
		cfg := pyConfig(t, "c.json", map[string]any{"bundle_dir": specBundle(t), "state_dir": refState})
		if r := python(t, "info", "--config", cfg); r.code != 0 {
			t.Fatal(r.stderr)
		}
		if err := os.WriteFile(filepath.Join(refState, "audit.jsonl"), append(append([]byte{}, original...), notUTF8...), 0o600); err != nil {
			t.Fatal(err)
		}
		if r := python(t, "audit", "verify", "--config", cfg); r.code != 1 || !strings.Contains(r.stdout+r.stderr, "audit_broken") {
			t.Errorf("reference, audit log not UTF-8: %d %s %s", r.code, r.stdout, r.stderr)
		}
		_ = os.Remove(filepath.Join(refState, "audit.jsonl"))
		if err := os.WriteFile(filepath.Join(refState, "state.json"), notUTF8, 0o600); err != nil {
			t.Fatal(err)
		}
		if r := python(t, "info", "--config", cfg); r.code != 1 || !strings.Contains(r.stdout+r.stderr, "state_io") {
			t.Errorf("reference, state.json not UTF-8: %d %s %s", r.code, r.stdout, r.stderr)
		}
	}

	// a bundle file -> bundle_io
	for _, name := range []string{"policies.json", "entities.json", "catalog.json", "roles.json", "policies/x.cedar", "bundle.sig.json"} {
		dir := t.TempDir()
		copyDir(t, specBundle(t), dir)
		writeBundle(t, dir, map[string]any{name: notUTF8})
		cfg := map[string]any{"bundle_dir": dir}
		want := "bundle_io"
		if name == "bundle.sig.json" {
			// only read when a signature is required; then it is a malformed signature file
			cfg["bundle_public_key"], want = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "bundle_signature"
		}
		_, err := NewEngine(cfg)
		if err == nil || err.(*EngineError).Code != want {
			t.Errorf("%s not UTF-8: %v, want %s", name, err, want)
		}
		if havePython(t) {
			args := []string{"info", "--config", pyConfig(t, "c.json", cfg)}
			if r := python(t, args...); r.code != 1 || !strings.Contains(r.stderr, want+":") {
				t.Errorf("reference, %s not UTF-8: %d %q, want %s", name, r.code, r.stderr, want)
			}
		}
	}

	// entities.json that is not a list of objects -> entities_parse
	for _, text := range []string{`null`, `0`, `false`, `true`, `{}`, `""`, `"x"`, `5`, `{"uid": {"type": "T", "id": "x"}}`, `[5]`, `["x"]`, `[null]`, `[[]]`,
		`[{"uid": {"type": "T", "id": "x"}}, 5]`, `[{}]`, `[{"uid": 5}]`, `[{"uid": {"__entity": {"type": "T"}}}]`} {
		dir := t.TempDir()
		copyDir(t, specBundle(t), dir)
		writeBundle(t, dir, map[string]any{"entities.json": text})
		if _, err := NewEngine(map[string]any{"bundle_dir": dir}); err == nil || err.(*EngineError).Code != "entities_parse" {
			t.Errorf("entities.json %s: %v, want entities_parse", text, err)
		}
	}
	for _, text := range []string{`[]`, `[{"uid": {"type": "T", "id": "x"}}]`, `[{"uid": {"__entity": {"type": "User", "id": "x"}}, "attrs": {"region": "EU"}}]`} {
		dir := t.TempDir()
		writeBundle(t, dir, map[string]any{"policies.json": `{"policies": {}}`, "entities.json": text})
		eng, err := NewEngine(map[string]any{"bundle_dir": dir})
		if err != nil {
			t.Errorf("entities.json %s: %v", text, err)
			continue
		}
		eng.Close()
	}
}

// Creating the signing key is safe when several engines start on an empty state directory at once.
func TestStrictSigningKeyCreationRace(t *testing.T) {
	for round := 0; round < 5; round++ {
		state := filepath.Join(t.TempDir(), "state")
		const starters = 12
		var wg sync.WaitGroup
		kids := make([]any, starters)
		errs := make([]error, starters)
		start := make(chan struct{})
		for i := 0; i < starters; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				e, err := NewEngine(map[string]any{"bundle_dir": specBundle(t), "state_dir": state})
				if err != nil {
					errs[i] = err
					return
				}
				defer e.Close()
				kids[i] = e.Call("info", map[string]any{})["key_id"]
			}(i)
		}
		close(start)
		wg.Wait()
		for i := range kids {
			if errs[i] != nil {
				t.Fatalf("round %d, engine %d: %v", round, i, errs[i])
			}
			if kids[i] != kids[0] || kids[i] == nil {
				t.Fatalf("round %d: engines ended up with different keys: %v", round, kids)
			}
		}
		private, _ := os.ReadFile(filepath.Join(state, "signing_key.pk8.b64"))
		public, _ := os.ReadFile(filepath.Join(state, "signing_key.pub.b64"))
		priv, kerr := loadPrivate(string(private))
		if kerr != nil || string(public) == "" {
			t.Fatalf("round %d: key files: %v %q", round, kerr, public)
		}
		if id, _ := KeyID(string(public)); id != kids[0] || sha256Hex(priv.Public().(ed25519.PublicKey))[:16] != id {
			t.Errorf("round %d: the public key file does not belong to the private key in use", round)
		}
	}
	// and across processes: this port's CLI and (when present) the reference, started together
	state := filepath.Join(t.TempDir(), "state")
	cfg := pyConfig(t, "c.json", map[string]any{"bundle_dir": specBundle(t), "state_dir": state})
	bin := goCLI(t)
	const procs = 8
	out := make([]cliResult, procs)
	var wg sync.WaitGroup
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 1 && havePython(t) {
				out[i] = python(t, "info", "--config", cfg)
			} else {
				out[i] = runCmd(t, cleanEnv(), "", nil, bin, "info", "--config", cfg)
			}
		}(i)
	}
	wg.Wait()
	for i, r := range out {
		if r.code != 0 || r.json(t)["key_id"] != out[0].json(t)["key_id"] {
			t.Errorf("process %d: exit %d, %s %s (first key %v)", i, r.code, r.stdout, r.stderr, out[0].json(t)["key_id"])
		}
	}
}

// Revoke by user (offboarding), and `task` in token results.
func TestRevokeUser(t *testing.T) {
	e, state := newTestEngine(t, nil)
	at := func(in map[string]any, now int64) map[string]any {
		in["now"] = now
		return in
	}
	root := mustOK(t, e.Call("issue_token", at(map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap(), "task": "ticket-1"}, testNow)))
	child := mustOK(t, e.Call("exchange_token", at(map[string]any{"subject_token": root["token"], "actor": "refund-helper", "ttl": 300}, testNow)))
	roleTok := mustOK(t, e.Call("issue_token", at(map[string]any{"user": "alice", "agent": "support-bot", "role": "support-agent"}, testNow)))
	if root["task"] != "ticket-1" || child["task"] != "ticket-1" || root["role"] != nil {
		t.Errorf("task / role in results: %s %s", Canon(root["task"]), Canon(child["task"]))
	}
	if v, has := roleTok["task"]; !has || v != nil || roleTok["role"] != "support-agent" {
		t.Errorf("a token without a task has task null: %s", Canon(roleTok))
	}
	bob := mustOK(t, e.Call("issue_token", at(map[string]any{"user": "bob", "agent": "support-bot", "cap": fullCap()}, testNow)))
	later := mustOK(t, e.Call("issue_token", at(map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap()}, testNow+11)))
	atCut := mustOK(t, e.Call("issue_token", at(map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap()}, testNow+10)))

	// a user that is not a non-empty string is invalid_input, whatever else is there
	for _, u := range []any{"", 5, nil, []any{"alice"}, true, map[string]any{}} {
		if r := e.Call("revoke", map[string]any{"user": u, "token_id": root["token_id"], "token": root["token"]}); errCode(r) != "invalid_input" {
			t.Errorf("revoke user %v: %s", u, Canon(r))
		}
	}
	if r := e.Call("authorize", at(readRequest(root["token"]), testNow+1)); r["effect"] != "allow" {
		t.Fatalf("nothing was revoked yet: %s", Canon(r))
	}

	// `user` takes precedence over token and token_id
	r := e.Call("revoke", at(map[string]any{"user": "alice", "by": "hr", "token_id": bob["token_id"], "token": bob["token"]}, testNow+10))
	if Canon(r) != `{"issued_up_to":1700000010,"ok":true,"revoked_user":"alice"}` {
		t.Fatalf("revoke user: %s", Canon(r))
	}
	for name, tok := range map[string]any{"root": root["token"], "sub-agent": child["token"], "role token": roleTok["token"], "issued at the cut-off": atCut["token"]} {
		d := e.Call("authorize", at(readRequest(tok), testNow+12))
		p, _ := d["principal"].(map[string]any)
		if d["reason"] != "token_revoked" || d["rule"] != "DELEGATE-TOKEN-REVOKED" || p["user"] != "alice" {
			t.Errorf("%s after revoking the user: %s", name, Canon(d))
		}
		if i := e.Call("inspect_token", map[string]any{"token": tok, "now": testNow + 12}); i["valid"] != false || i["reason"] != "token_revoked" {
			t.Errorf("%s inspect: %s", name, Canon(i))
		}
		if x := e.Call("exchange_token", map[string]any{"subject_token": tok, "actor": "summarizer", "ttl": 30, "now": testNow + 12}); errCode(x) != "token_revoked" {
			t.Errorf("%s exchange: %s", name, Canon(x))
		}
	}
	// tokens issued later, and other users, are unaffected
	if d := e.Call("authorize", at(readRequest(later["token"]), testNow+12)); d["effect"] != "allow" {
		t.Errorf("a token issued after the cut-off: %s", Canon(d))
	}
	if d := e.Call("authorize", at(readRequest(bob["token"]), testNow+12)); d["effect"] != "allow" {
		t.Errorf("another user's token (and its id was not revoked): %s", Canon(d))
	}
	// expiry is still reported as expiry; a token-id revocation is checked first
	if d := e.Call("authorize", at(readRequest(root["token"]), testNow+5000)); d["reason"] != "token_expired" {
		t.Errorf("an expired token of a revoked user: %s", Canon(d))
	}
	mustOK(t, e.Call("revoke", at(map[string]any{"token_id": root["token_id"]}, testNow+12)))
	if d := e.Call("authorize", at(readRequest(child["token"]), testNow+12)); d["reason"] != "token_revoked" || !strings.Contains(d["detail"].(string), root["token_id"].(string)) {
		t.Errorf("the token-id revocation comes first: %s", Canon(d))
	}

	// the cut-off never moves back: a second revoke with an earlier clock keeps the later one
	back := e.Call("revoke", at(map[string]any{"user": "alice", "by": "slow-clock"}, testNow+3))
	if Canon(back) != `{"issued_up_to":1700000010,"ok":true,"revoked_user":"alice"}` {
		t.Errorf("a revoke with an earlier clock: %s", Canon(back))
	}
	if d := e.Call("authorize", at(readRequest(atCut["token"]), testNow+12)); d["reason"] != "token_revoked" {
		t.Errorf("an earlier clock revived a dead token: %s", Canon(d))
	}
	if d := e.Call("authorize", at(readRequest(later["token"]), testNow+12)); d["effect"] != "allow" {
		t.Errorf("a token issued after the cut-off: %s", Canon(d))
	}
	var slow map[string]any
	for _, rec := range e.Call("audit_tail", map[string]any{"n": 10})["records"].([]any) {
		if m := rec.(map[string]any); m["by"] == "slow-clock" {
			slow = m
		}
	}
	if slow["event"] != "user_revoked" || slow["issued_up_to"] != testNow+10 || slow["ts"] != testNow+3 || slow["by"] != "slow-clock" {
		t.Errorf("the audit record of the second revoke: %s", Canon(slow))
	}

	// the audit record, and state.json
	tail := e.Call("audit_tail", map[string]any{"n": 100})
	var found map[string]any
	for _, rec := range tail["records"].([]any) {
		if m := rec.(map[string]any); m["event"] == "user_revoked" && m["by"] == "hr" {
			found = m
		}
	}
	if found["user"] != "alice" || found["issued_up_to"] != testNow+10 || found["by"] != "hr" || found["ts"] != testNow+10 {
		t.Errorf("audit event user_revoked: %s", Canon(found))
	}
	raw, _ := os.ReadFile(filepath.Join(state, "state.json"))
	if doc := mustParse(t, string(raw)).(map[string]any); Canon(doc["revoked_users"]) != `{"alice":1700000010}` {
		t.Errorf("state.json revoked_users: %s", Canon(doc["revoked_users"]))
	}
	// entries are never pruned: issuing a budgeted token years later prunes the rest, not this
	mustOK(t, e.Call("issue_token", at(map[string]any{"user": "bob", "agent": "support-bot", "cap": fullCap()}, testNow+400*86400)))
	raw, _ = os.ReadFile(filepath.Join(state, "state.json"))
	doc := mustParse(t, string(raw)).(map[string]any)
	if Canon(doc["revoked_users"]) != `{"alice":1700000010}` || len(doc["revoked"].(map[string]any)) != 0 {
		t.Errorf("after pruning: revoked_users %s, revoked %s", Canon(doc["revoked_users"]), Canon(doc["revoked"]))
	}

	// a state file written by an engine that does not know the key: a missing key is an empty object
	delete(doc, "revoked_users")
	writeJSONFile(t, filepath.Join(state, "state.json"), doc)
	if d := e.Call("authorize", at(readRequest(later["token"]), testNow+12)); d["effect"] != "allow" {
		t.Errorf("state.json without revoked_users: %s", Canon(d))
	}
	mustOK(t, e.Call("revoke", at(map[string]any{"user": "bob"}, testNow+13)))
	raw, _ = os.ReadFile(filepath.Join(state, "state.json"))
	if doc := mustParse(t, string(raw)).(map[string]any); Canon(doc["revoked_users"]) != `{"bob":1700000013}` {
		t.Errorf("state.json after the next revoke: %s", Canon(doc["revoked_users"]))
	}
	// revoked_users that is not an object is a corrupt state file; an entry that is not an integer revokes nothing
	writeJSONFile(t, filepath.Join(state, "state.json"), map[string]any{"revoked_users": []any{"alice"}})
	if d := e.Call("authorize", at(readRequest(later["token"]), testNow+12)); errCode(d) != "state_io" {
		t.Errorf("revoked_users a list: %s", Canon(d))
	}
	writeJSONFile(t, filepath.Join(state, "state.json"), map[string]any{"revoked_users": map[string]any{"alice": "always", "bob": true}})
	if d := e.Call("authorize", at(readRequest(later["token"]), testNow+12)); d["effect"] != "allow" {
		t.Errorf("a cut-off that is not an integer: %s", Canon(d))
	}

	// over REST it is an admin operation
	srv, _ := startServer(t, nil)
	if code, body, _ := do(t, "POST", srv.URL+"/v1/admin/revoke", testPep, []byte(`{"user":"alice"}`)); code != 401 {
		t.Errorf("revoke user with the pep key: %d %v", code, body)
	}
	if r := NewClient(srv.URL, testPep, testAdmin).Call("revoke", map[string]any{"user": "alice", "now": testNow}); r["revoked_user"] != "alice" || r["issued_up_to"] != testNow {
		t.Errorf("revoke user through the client: %s", Canon(r))
	}
}

// An empty signing key file is a key still being written: wait for it, then
// fail with state_io. Never "no key".
func TestStrictEmptySigningKeyFile(t *testing.T) {
	private, public, _ := Keygen()
	wantKid, _ := KeyID(public)
	defer func(d time.Duration) { keyWait = d }(keyWait)

	for _, initial := range []string{"", " \n\t"} {
		// filled 400 ms later: the engine starts with that key and can issue
		keyWait = 10 * time.Second
		state := t.TempDir()
		kp := filepath.Join(state, "signing_key.pk8.b64")
		if err := os.WriteFile(kp, []byte(initial), 0o600); err != nil {
			t.Fatal(err)
		}
		go func() {
			time.Sleep(400 * time.Millisecond)
			_ = os.WriteFile(kp, []byte(private+"\n"), 0o600)
		}()
		started := time.Now()
		e, err := NewEngine(ConformanceConfig(specBundle(t), state, nil))
		if err != nil {
			t.Fatalf("key file %q filled 400 ms later: %v", initial, err)
		}
		if waited := time.Since(started); waited < 300*time.Millisecond {
			t.Errorf("the engine did not wait for the key (%v)", waited)
		}
		info := e.Call("info", map[string]any{})
		if info["can_issue"] != true || info["key_id"] != wantKid || info["public_key"] != public {
			t.Errorf("info after waiting for the key: %s", Canon(info))
		}
		token := issue(t, e, nil)["token"]
		if r := e.Call("authorize", readRequest(token)); r["effect"] != "allow" {
			t.Errorf("a token signed with the awaited key: %s", Canon(r))
		}
		e.Close()

		// empty forever: state_io, and the file is left alone
		keyWait = 300 * time.Millisecond
		state = t.TempDir()
		kp = filepath.Join(state, "signing_key.pk8.b64")
		if err := os.WriteFile(kp, []byte(initial), 0o600); err != nil {
			t.Fatal(err)
		}
		started = time.Now()
		e, err = NewEngine(ConformanceConfig(specBundle(t), state, nil))
		if e != nil {
			e.Close()
			t.Fatalf("an engine started on an empty key file %q: %s", initial, Canon(e.Call("info", map[string]any{})))
		}
		if ee, ok := err.(*EngineError); !ok || ee.Code != "state_io" {
			t.Errorf("empty key file %q: %v, want state_io", initial, err)
		}
		if waited := time.Since(started); waited < 250*time.Millisecond || waited > 5*time.Second {
			t.Errorf("waited %v for a deadline of 300 ms", waited)
		}
		if raw, _ := os.ReadFile(kp); string(raw) != initial {
			t.Errorf("the empty key file was overwritten: %q", raw)
		}
		if _, err := os.Stat(filepath.Join(state, "signing_key.pub.b64")); err == nil {
			t.Error("a public key file was written for a key that does not exist")
		}
	}
	// the CLI, as in the report: exit 1 with state_io, not ok with can_issue false
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "signing_key.pk8.b64"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goCLI(t), "info", "--bundle", specBundle(t), "--state", state)
	cmd.Env = cleanEnv()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		if cmd.ProcessState.ExitCode() != 1 || !strings.Contains(out.String(), "state_io") || strings.Contains(out.String(), "can_issue") {
			t.Errorf("CLI on an empty key file: exit %d, %s", cmd.ProcessState.ExitCode(), out.String())
		}
	case <-time.After(1500 * time.Millisecond):
		// still waiting for the key, as it should (the deadline is 30 s): give it one
		if err := os.WriteFile(filepath.Join(state, "signing_key.pk8.b64"), []byte(private), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil || !strings.Contains(out.String(), `"can_issue": true`) || !strings.Contains(out.String(), wantKid) {
			t.Errorf("CLI after the key appeared: %v %s", err, out.String())
		}
	}
	// a key file that is not a key, or not text, is an error too
	for _, content := range []string{"not a key", "\xff\xfe"} {
		state := t.TempDir()
		if err := os.WriteFile(filepath.Join(state, "signing_key.pk8.b64"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if e, err := NewEngine(ConformanceConfig(specBundle(t), state, nil)); err == nil {
			e.Close()
			t.Errorf("an engine started on the key file %q", content)
		}
	}
	// no temporary file is left behind after creating a key
	state = t.TempDir()
	e, err := NewEngine(ConformanceConfig(specBundle(t), state, nil))
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	entries, _ := os.ReadDir(state)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("left behind: %s", entry.Name())
		}
	}
	if st, err := os.Stat(filepath.Join(state, "signing_key.pk8.b64")); err != nil || st.Mode().Perm() != 0o600 || st.Size() == 0 {
		t.Errorf("the key file: %v", err)
	}
}

// F-1: an ancestor's budget travels in the `lim` claim, so a verify-only
// engine with its own state directory enforces it too.
func TestAncestorBudgetTravelsWithTheToken(t *testing.T) {
	refunds := func(budget int64) map[string]any {
		return map[string]any{"actions": []any{"create"}, "resources": []any{"billing.refund/*"}, "budget": map[string]any{"EUR": budget}}
	}
	spend := func(token any) map[string]any { return spendRequest(token, 5000, testNow) }
	verifierConfig := func(state string, public any) map[string]any {
		return map[string]any{"bundle_dir": specBundle(t), "state_dir": state, "allow_test_clock": true, "verify_only": true, "trusted_keys": []any{public}}
	}
	type family struct{ parent, kid0, kid1, kid2, grand map[string]any }
	make3 := func(call func(op string, in any) map[string]any) family {
		var f family
		f.parent = call("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "now": testNow, "cap": refunds(10000)})
		kid := func() map[string]any {
			return call("exchange_token", map[string]any{"subject_token": f.parent["token"], "actor": "refund-helper", "ttl": 300, "now": testNow, "cap": refunds(6000)})
		}
		f.kid0, f.kid1, f.kid2 = kid(), kid(), kid()
		f.grand = call("exchange_token", map[string]any{"subject_token": f.kid2["token"], "actor": "summarizer", "ttl": 60, "now": testNow, "cap": refunds(6000)})
		for _, r := range []map[string]any{f.parent, f.kid0, f.kid1, f.kid2, f.grand} {
			if r["ok"] != true {
				t.Fatalf("issuing: %s", Canon(r))
			}
		}
		return f
	}
	checkClaims := func(who string, inspect func(token any) map[string]any, f family) {
		t.Helper()
		pid, kid := f.parent["token_id"].(string), f.kid2["token_id"].(string)
		if c := inspect(f.parent["token"])["claims"].(map[string]any); c["lim"] != nil {
			t.Errorf("%s: a root token has no lim: %s", who, Canon(c))
		}
		if c := inspect(f.kid0["token"])["claims"].(map[string]any); Canon(c["lim"]) != Canon(map[string]any{pid: map[string]any{"EUR": int64(10000)}}) {
			t.Errorf("%s: lim of a child: %s", who, Canon(c["lim"]))
		}
		want := map[string]any{pid: map[string]any{"EUR": int64(10000)}, kid: map[string]any{"EUR": int64(6000)}}
		if c := inspect(f.grand["token"])["claims"].(map[string]any); Canon(c["lim"]) != Canon(want) {
			t.Errorf("%s: lim of a grandchild: %s", who, Canon(c["lim"]))
		}
	}
	// two children spend 5000 each of the parent's 10000; the third child, and its child, get nothing
	checkSpends := func(who string, call func(op string, in any) map[string]any, f family) {
		t.Helper()
		for i, tok := range []any{f.kid0["token"], f.kid1["token"]} {
			if r := call("authorize", spend(tok)); r["effect"] != "allow" {
				t.Errorf("%s: spend %d: %s", who, i, Canon(r))
			}
		}
		for name, tok := range map[string]any{"third child": f.kid2["token"], "grandchild": f.grand["token"]} {
			if r := call("authorize", spend(tok)); r["effect"] != "deny" || r["reason"] != "budget_exceeded" {
				t.Errorf("%s: the %s overspent the parent's budget: %s", who, name, Canon(r))
			}
		}
	}

	// Go issues, a Go verifier with its own state enforces
	issuer, _ := newTestEngine(t, nil)
	public := issuer.Call("info", map[string]any{})["public_key"]
	f := make3(issuer.Call)
	checkClaims("go", func(token any) map[string]any {
		return issuer.Call("inspect_token", map[string]any{"token": token, "now": testNow})
	}, f)
	verifier, err := NewEngine(verifierConfig(filepath.Join(t.TempDir(), "verifier"), public))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	checkSpends("go verifier", verifier.Call, f)
	// no ancestor with a budget: no lim claim at all
	plain := mustOK(t, issuer.Call("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "now": testNow, "cap": map[string]any{"actions": []any{"read"}, "resources": []any{"*"}}}))
	plainKid := mustOK(t, issuer.Call("exchange_token", map[string]any{"subject_token": plain["token"], "actor": "refund-helper", "ttl": 60, "now": testNow}))
	if c := issuer.Call("inspect_token", map[string]any{"token": plainKid["token"], "now": testNow})["claims"].(map[string]any); c["lim"] != nil {
		t.Errorf("lim without any budget: %s", Canon(c))
	}
	if _, has := c2(issuer, plainKid["token"])["lim"]; has {
		t.Error("the lim claim must be absent, not null or empty")
	}
	// state.limits wins over lim when this engine has it: the issuer still enforces as before
	g := make3(issuer.Call)
	checkSpends("go issuer", issuer.Call, g)

	// a forged or malformed lim is not a token
	private, _, _ := Keygen()
	keys, _ := newKeyring(private, nil)
	own, err := NewEngine(map[string]any{"bundle_dir": specBundle(t), "signing_key": private, "allow_test_clock": true})
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	signed := func(lim any, drop bool) string {
		claims := map[string]any{"iss": "smartdelegate://local", "aud": "smartdelegate", "sub": "user:alice", "iat": testNow, "exp": testNow + 600, "jti": "t-2",
			"act": map[string]any{"sub": "agent:refund-helper", "act": map[string]any{"sub": "agent:support-bot"}}, "anc": []any{"t-1"}, "cap": refunds(6000), "lim": lim}
		if drop {
			delete(claims, "lim")
		}
		tok, serr := keys.sign(claims)
		if serr != nil {
			t.Fatal(serr)
		}
		return tok
	}
	bad := map[string]any{"a string": "x", "a list": []any{}, "null": nil, "a number": 5, "a number for a budget": map[string]any{"a": 5}, "a negative amount": map[string]any{"a": map[string]any{"EUR": -1}},
		"a string amount": map[string]any{"a": map[string]any{"EUR": "9"}}, "a float amount": map[string]any{"a": map[string]any{"EUR": 9.0}}, "a boolean amount": map[string]any{"a": map[string]any{"EUR": true}},
		"a null amount": map[string]any{"a": map[string]any{"EUR": nil}}, "a list for a budget": map[string]any{"a": []any{}}, "a null budget": map[string]any{"a": nil},
		"one good and one bad": map[string]any{"a": map[string]any{"EUR": 1}, "b": map[string]any{"EUR": map[string]any{}}}}
	good := map[string]any{"empty": map[string]any{}, "an empty budget": map[string]any{"t-1": map[string]any{}}, "zero": map[string]any{"t-1": map[string]any{"EUR": 0}},
		"two currencies": map[string]any{"t-1": map[string]any{"EUR": 1, "USD": 2}, "t-0": map[string]any{"EUR": 3}}}
	for name, lim := range bad {
		for op, in := range map[string]map[string]any{"inspect_token": {"token": signed(lim, false), "now": testNow}, "authorize": spend(signed(lim, false)),
			"exchange_token": {"subject_token": signed(lim, false), "actor": "summarizer", "now": testNow}} {
			r := own.Call(op, in)
			reason, _ := r["reason"].(string)
			if reason == "" {
				reason = errCode(r)
			}
			if reason != "token_invalid" {
				t.Errorf("lim %s, %s: %s, want token_invalid", name, op, Canon(r))
			}
		}
	}
	for name, lim := range good {
		if r := own.Call("inspect_token", map[string]any{"token": signed(lim, false), "now": testNow}); r["valid"] != true {
			t.Errorf("lim %s: %s", name, Canon(r))
		}
	}
	if r := own.Call("inspect_token", map[string]any{"token": signed(nil, true), "now": testNow}); r["valid"] != true {
		t.Errorf("no lim (a token from before the claim existed): %s", Canon(r))
	}
	// the limit in lim is used: 6000 own budget, ancestor limit 4000 in the claim, nothing in state
	if r := own.Call("authorize", spend(signed(map[string]any{"t-1": map[string]any{"EUR": 4000}}, false))); r["reason"] != "budget_exceeded" {
		t.Errorf("an ancestor limit of 4000 from lim, spend 5000: %s", Canon(r))
	}
	if r := own.Call("authorize", spend(signed(map[string]any{"t-1": map[string]any{"EUR": 5000}, "other": map[string]any{"EUR": 0}, "t-0": map[string]any{"USD": 0}}, false))); r["effect"] != "allow" {
		t.Errorf("an ancestor limit of 5000 from lim, spend 5000 (limits of tokens that are not ancestors, or in another currency, do not count): %s", Canon(r))
	}

	if !havePython(t) {
		t.Logf("not run against the Python reference: %s", pyReason)
		return
	}
	// Go issues; the reference, verify-only with its own state directory, denies the over-budget spend
	h := make3(issuer.Call)
	refVerifier := pyConfig(t, "verifier.json", verifierConfig(filepath.Join(t.TempDir(), "ref-verifier"), public))
	refCall := func(cfg string) func(op string, in any) map[string]any {
		return func(op string, in any) map[string]any { return pythonCall(t, cfg, op, in) }
	}
	checkClaims("reference reading Go tokens", func(token any) map[string]any {
		return pythonCall(t, refVerifier, "inspect_token", map[string]any{"token": token, "now": testNow})
	}, h)
	checkSpends("reference verifier, Go tokens", refCall(refVerifier), h)

	// the reference issues; a Go verify-only engine with its own state directory denies it
	refIssuer := pyConfig(t, "issuer.json", map[string]any{"bundle_dir": specBundle(t), "state_dir": filepath.Join(t.TempDir(), "ref-issuer"), "allow_test_clock": true})
	k := make3(refCall(refIssuer))
	goVerifier, err := NewEngine(verifierConfig(filepath.Join(t.TempDir(), "go-verifier"), pythonCall(t, refIssuer, "info", map[string]any{})["public_key"]))
	if err != nil {
		t.Fatal(err)
	}
	defer goVerifier.Close()
	checkClaims("go reading reference tokens", func(token any) map[string]any {
		return goVerifier.Call("inspect_token", map[string]any{"token": token, "now": testNow})
	}, k)
	checkSpends("go verifier, reference tokens", goVerifier.Call, k)

	// malformed lim: the reference refuses the same tokens
	trusting := pyConfig(t, "trusting.json", map[string]any{"bundle_dir": specBundle(t), "allow_test_clock": true, "verify_only": true, "trusted_keys": []any{keys.publicB64}})
	for name, lim := range bad {
		if r := pythonCall(t, trusting, "inspect_token", map[string]any{"token": signed(lim, false), "now": testNow}); r["reason"] != "token_invalid" {
			t.Errorf("reference, lim %s: %s", name, Canon(r))
		}
	}
	for name, lim := range good {
		if r := pythonCall(t, trusting, "inspect_token", map[string]any{"token": signed(lim, false), "now": testNow}); r["valid"] != true {
			t.Errorf("reference, lim %s: %s", name, Canon(r))
		}
	}
}

// c2 is the claims of a token as its payload says, without the engine's defaults.
func c2(e *Engine, token any) map[string]any {
	parts := strings.Split(token.(string), ".")
	raw, _ := b64uDec(parts[1])
	v, _ := ParseJSON(raw)
	m, _ := v.(map[string]any)
	return m
}

// An approval is bound to resource.attrs, and the approval id is the same in every port.
func TestApprovalIsBoundToResourceAttrs(t *testing.T) {
	e, _ := newTestEngine(t, nil)
	token := issue(t, e, nil)["token"].(string)
	// the request as JSON text, so that the key order of attrs is the test's and not a map's
	request := func(tok, attrs string) []byte {
		res := `{"path":"billing.refund","id":"r-1"`
		if attrs != "" {
			res += `,"attrs":` + attrs
		}
		return []byte(`{"token":"` + tok + `","action":"create","resource":` + res + `},"context":{"spend":{"currency":"EUR","amount":15000},"note":"\u00e9"},"now":1700000000}`)
	}
	ask := func(attrs string) map[string]any {
		t.Helper()
		v, err := ParseJSON(e.CallJSON("authorize", request(token, attrs)))
		if err != nil {
			t.Fatal(err)
		}
		return v.(map[string]any)
	}
	id := func(r map[string]any) string {
		t.Helper()
		a, _ := r["approval"].(map[string]any)
		s, _ := a["id"].(string)
		if r["reason"] != "approval_required" || len(s) != 24 {
			t.Fatalf("expected a held request: %s", Canon(r))
		}
		return s
	}
	emp1, emp2 := `{"employee":"emp-1"}`, `{"employee":"emp-2"}`
	nested := `{"z":{"b":[1,"x",true],"a":{"n":-9223372036854775808}},"name":"Zo\u00eb \ud83d\ude00 \u2028","count":42,"owner":{"__entity":{"type":"User","id":"bob"}}}`
	shuffled := ` { "count" : 42, "owner": {"__entity": {"id": "bob", "type": "User"}}, "name": "Zo\u00eb \ud83d\ude00 \u2028", "z": {"a": {"n": -9223372036854775808}, "b": [1, "x", true]} } `
	variants := map[string]string{"no attrs": "", "attrs null": "null", "attrs empty": "{}", "emp-1": emp1, "emp-2": emp2, "nested": nested, "nested, key order shuffled": shuffled,
		"integer": `{"n":1}`, "string of the integer": `{"n":"1"}`, "boolean": `{"n":true}`}
	ids := map[string]string{}
	for name, attrs := range variants {
		ids[name] = id(ask(attrs))
	}
	// absent, null and {} are the same request; key order does not matter; anything else is another request
	if ids["no attrs"] != ids["attrs null"] || ids["no attrs"] != ids["attrs empty"] || ids["nested"] != ids["nested, key order shuffled"] {
		t.Errorf("ids that must be equal: %v", ids)
	}
	distinct := map[string]bool{}
	for _, name := range []string{"no attrs", "emp-1", "emp-2", "nested", "integer", "string of the integer", "boolean"} {
		distinct[ids[name]] = true
	}
	if len(distinct) != 7 {
		t.Errorf("requests that differ in attrs must have different approval ids: %v", ids)
	}
	want := hashValue(mustParse(t, `{"user":"alice","chain":["support-bot"],"tenant":null,"action":"create","resource":"billing.refund/r-1","attrs":{"employee":"emp-1"},
		"context":{"spend":{"currency":"EUR","amount":15000},"note":"\u00e9"},"label":"refund-over-100-eur"}`))[:24]
	if ids["emp-1"] != want {
		t.Errorf("approval id %s, the formula of spec/PORTING.md gives %s", ids["emp-1"], want)
	}

	// approved for emp-1: emp-2 and "no attrs" still wait; emp-1 goes through once
	mustOK(t, e.Call("approve", map[string]any{"approval_id": ids["emp-1"], "by": "bob", "now": testNow}))
	for _, other := range []string{emp2, "", nested} {
		if r := ask(other); r["reason"] != "approval_required" {
			t.Errorf("an approval for emp-1 was used by a request with attrs %q: %s", other, Canon(r))
		}
	}
	if granted := e.Call("approvals", map[string]any{})["granted"].(map[string]any); len(granted) != 1 || granted[ids["emp-1"]] == nil {
		t.Errorf("the approval for emp-1 must still be there: %s", Canon(granted))
	}
	first := ask(emp1)
	if first["effect"] != "allow" || Canon(first["obligations"].(map[string]any)["approved"]) != `{"by":"bob","id":"`+ids["emp-1"]+`"}` {
		t.Errorf("the approved request: %s", Canon(first))
	}
	if granted := e.Call("approvals", map[string]any{})["granted"].(map[string]any); len(granted) != 0 {
		t.Errorf("an approval is good for one call: %s", Canon(granted))
	}

	if !havePython(t) {
		t.Logf("approval ids not compared with the Python reference: %s", pyReason)
		return
	}
	// the reference computes the same id for every variant (its own token: the id does not depend on it)
	cfg := pyConfig(t, "c.json", map[string]any{"bundle_dir": specBundle(t), "state_dir": filepath.Join(t.TempDir(), "state"), "allow_test_clock": true})
	theirToken := pythonCall(t, cfg, "issue_token", map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap(), "now": testNow})["token"].(string)
	for name, attrs := range variants {
		r := runCmd(t, pythonEnv(t), "", request(theirToken, attrs), "python3", "-m", "sf_smartdelegate", "call", "authorize", "--input", "-", "--config", cfg).json(t)
		if got := id(r); got != ids[name] {
			t.Errorf("%s: approval id differs: go %s, reference %s", name, ids[name], got)
		}
	}
	// and across the two: approved in the reference's state for emp-1, used there only by emp-1
	if r := pythonCall(t, cfg, "approve", map[string]any{"approval_id": ids["emp-1"], "by": "bob", "now": testNow}); r["ok"] != true {
		t.Fatalf("reference approve: %s", Canon(r))
	}
	other := runCmd(t, pythonEnv(t), "", request(theirToken, emp2), "python3", "-m", "sf_smartdelegate", "call", "authorize", "--input", "-", "--config", cfg).json(t)
	same := runCmd(t, pythonEnv(t), "", request(theirToken, emp1), "python3", "-m", "sf_smartdelegate", "call", "authorize", "--input", "-", "--config", cfg).json(t)
	if other["reason"] != "approval_required" || same["effect"] != "allow" {
		t.Errorf("reference: emp-2 %s, emp-1 %s", Canon(other["reason"]), Canon(same["effect"]))
	}
}
