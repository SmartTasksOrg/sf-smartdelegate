package smartdelegate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The README example: issue a role token, authorize, filter.
func TestReadmeExample(t *testing.T) {
	engine, err := NewEngine(map[string]any{"bundle_dir": specBundle(t), "state_dir": filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	issued := engine.Call("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "role": "support-agent"})
	if issued["ok"] != true || issued["role"] != "support-agent" {
		t.Fatalf("issue_token: %s", Canon(issued))
	}
	request := map[string]any{"token": issued["token"], "action": "read", "resource": map[string]any{"path": "crm.customer", "id": "c-1"}}
	decision := engine.Call("authorize", request)
	if decision["effect"] != "allow" || decision["rule"] != "DELEGATE-POLICY-PERMIT" {
		t.Fatalf("authorize: %s", Canon(decision))
	}
	request["data"] = map[string]any{"id": "c-1", "name": "Ada", "ssn": "123-45-6789", "region": "EU"}
	filtered := engine.Call("filter", request)
	data, _ := filtered["data"].(map[string]any)
	if _, leaked := data["ssn"]; leaked || data["name"] != "Ada" || Canon(filtered["masked"]) != `["ssn"]` {
		t.Fatalf("filter: %s", Canon(filtered))
	}
	if info := engine.Call("info", nil); errCode(info) != "invalid_input" {
		t.Errorf("a nil payload is not an object: %s", Canon(info))
	}
	info := engine.Call("info", map[string]any{})
	if info["version"] != "0.3.0" || info["implementation"] != "go" {
		t.Errorf("info: %s", Canon(info))
	}
}

func TestNewEngineErrors(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		code string
		cfg  map[string]any
	}{
		{"invalid_input", nil},
		{"invalid_input", map[string]any{}},
		{"invalid_input", map[string]any{"bundle_dir": 5}},
		{"bundle_io", map[string]any{"bundle_dir": filepath.Join(dir, "missing")}},
		{"invalid_config", map[string]any{"bundle_dir": specBundle(t), "mode": "audit"}},
		{"invalid_input", map[string]any{"bundle_dir": specBundle(t), "idp": map[string]any{"issuer": "x", "audience": "y"}}},
		{"invalid_config", map[string]any{"bundle_dir": specBundle(t), "idp": map[string]any{"issuer": "x", "audience": "y", "jwks_file": filepath.Join(dir, "none.json")}}},
		{"invalid_config", map[string]any{"bundle_dir": specBundle(t), "idp": map[string]any{"jwks": map[string]any{}, "issuer": "x", "audience": "y", "group_map": map[string]any{"a": 1}}}},
		{"invalid_config", map[string]any{"bundle_dir": specBundle(t), "idp": map[string]any{"jwks": map[string]any{}, "issuer": "x", "audience": "y", "group_type": "not a type"}}},
		{"invalid_input", map[string]any{"bundle_dir": specBundle(t), "idp": map[string]any{"jwks": map[string]any{}, "audience": "y"}}},
		{"bundle_unsigned", map[string]any{"bundle_dir": specBundle(t), "bundle_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
		{"crypto", map[string]any{"bundle_dir": specBundle(t), "signing_key": "not base64"}},
		{"crypto", map[string]any{"bundle_dir": specBundle(t), "trusted_keys": []any{"AAAA"}}},
	}
	for _, c := range cases {
		e, err := NewEngine(c.cfg)
		if e != nil {
			e.Close()
		}
		ee, ok := err.(*EngineError)
		if !ok || ee.Code != c.code {
			t.Errorf("NewEngine(%s): got %v, want %s", Canon(c.cfg), err, c.code)
		}
	}
}

// Call never panics and never allows on input it cannot process.
func TestCallFailsClosed(t *testing.T) {
	e, state := newTestEngine(t, nil)
	token := issue(t, e, nil)["token"]
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	deep := any("x")
	for i := 0; i < maxDepth+5; i++ {
		deep = []any{deep}
	}
	payloads := []any{nil, 5, "x", []any{}, true, 1.5, func() {}, make(chan int), cyclic, map[string]any{"token": token, "context": deep},
		map[string]any{"token": token, "action": "read", "resource": map[string]any{"path": "crm.customer"}, "context": map[string]any{"x": 1.5}},
		map[string]any{"token": token, "action": "read", "resource": map[string]any{"path": "crm.customer"}, "context": map[string]any{"f": func() {}}},
		map[int]any{1: 2}, &cyclic}
	for _, op := range []string{"authorize", "filter", "explain", "issue_token", "exchange_token", "inspect_token", "apply_obligations", "revoke", "approve",
		"approvals", "audit_verify", "audit_tail", "info", "nonsense", ""} {
		for _, p := range payloads {
			r := e.Call(op, p)
			if r["effect"] == "allow" {
				t.Errorf("%s(%T) allowed: %s", op, p, Canon(r))
			}
			if _, isMap := p.(map[string]any); !isMap && p != nil {
				if _, isPtr := p.(*map[string]any); !isPtr && r["ok"] == true {
					t.Errorf("%s(%T) succeeded on a payload that is not an object", op, p)
				}
			}
		}
	}
	token = issue(t, e, nil)["token"] // the loop above revoked the first one
	if r := e.Call("authorize", readRequest(token)); r["effect"] != "allow" {
		t.Fatalf("the engine must still work: %s", Canon(r))
	}
	// Go integers of any width are integers; a float64 is a float and is refused in a context
	req := readRequest(token)
	req["context"] = map[string]any{"n": int32(7), "u": uint8(1), "list": []string{"a"}, "m": map[string]int{"k": 2}}
	if r := e.Call("authorize", req); r["effect"] != "allow" {
		t.Errorf("Go integer types in a context: %s", Canon(r))
	}
	req["context"] = map[string]any{"n": float64(7)}
	if r := e.Call("authorize", req); errCode(r) != "invalid_context" {
		t.Errorf("a float in a context must be refused: %s", Canon(r))
	}
	// the result is the caller's: changing it does not change the engine
	approvals := e.Call("approvals", map[string]any{})
	approvals["pending"].(map[string]any)["forged"] = map[string]any{"user": "x"}
	if again := e.Call("approvals", map[string]any{}); len(again["pending"].(map[string]any)) != 0 {
		t.Error("a result aliases engine state")
	}

	// a state file that cannot be read refuses every request
	if err := os.WriteFile(filepath.Join(state, "state.json"), []byte(`{"revoked": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.Call("authorize", readRequest(token)); errCode(r) != "state_io" {
		t.Errorf("corrupt state.json: %s", Canon(r))
	}
	if err := os.WriteFile(filepath.Join(state, "state.json"), []byte(`{"revoked": 5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.Call("authorize", readRequest(token)); errCode(r) != "state_io" {
		t.Errorf("malformed state.json: %s", Canon(r))
	}
	// values of the wrong type inside it are an internal error, never an allow
	if err := os.WriteFile(filepath.Join(state, "state.json"), []byte(`{"ledger": {}, "extra": [1, 2]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	limited := mustOK(t, e.Call("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap(), "now": testNow}))
	if err := os.WriteFile(filepath.Join(state, "state.json"), []byte(fmt.Sprintf(`{"ledger": {%q: {"EUR": "lots"}}}`, limited["token_id"])), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.Call("authorize", spendRequest(limited["token"], 5, testNow)); errCode(r) != "internal" {
		t.Errorf("a ledger entry that is not a number: %s", Canon(r))
	}
	e.Close()
	if r := e.Call("authorize", readRequest(token)); r["ok"] != false {
		t.Errorf("a closed engine must refuse: %s", Canon(r))
	}
	e.Close() // twice is fine
}

// A decision that cannot be recorded is refused.
func TestAuditFailureRefuses(t *testing.T) {
	e, state := newTestEngine(t, nil)
	token := issue(t, e, nil)["token"]
	mustOK(t, e.Call("authorize", readRequest(token)))
	log := filepath.Join(state, "audit.jsonl")
	original, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}

	// truncated while in use
	if err := os.WriteFile(log, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.Call("authorize", readRequest(token)); errCode(r) != "audit_io" || r["effect"] != nil {
		t.Errorf("truncated audit log: %s", Canon(r))
	}
	// dry_run writes no record, so it still answers
	dry := readRequest(token)
	dry["dry_run"] = true
	if r := e.Call("authorize", dry); r["effect"] != "allow" {
		t.Errorf("dry_run needs no audit record: %s", Canon(r))
	}
	// replaced by something that cannot be appended to
	if err := os.Remove(log); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(log, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"authorize", "filter"} {
		req := readRequest(token)
		req["data"] = map[string]any{"id": "c-1", "region": "EU"}
		if r := e.Call(op, req); errCode(r) != "audit_io" {
			t.Errorf("%s with an unwritable audit log: %s", op, Canon(r))
		}
	}
	if r := e.Call("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap()}); errCode(r) != "audit_io" || r["token"] != nil {
		t.Errorf("issue_token with an unwritable audit log: %s", Canon(r))
	}
	if err := os.Remove(log); err != nil {
		t.Fatal(err)
	}

	// another writer appended a record this engine cannot chain onto
	if err := os.WriteFile(log, append(original, []byte("not json\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.Call("authorize", readRequest(token)); errCode(r) != "audit_io" {
		t.Errorf("unreadable last record: %s", Canon(r))
	}
	// restored: the engine chains on and the log verifies
	if err := os.WriteFile(log, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.Call("authorize", readRequest(token)); r["effect"] != "allow" {
		t.Errorf("restored audit log: %s", Canon(r))
	}
	if r := e.Call("audit_verify", map[string]any{}); r["ok"] != true || r["records"] != int64(3) {
		t.Errorf("audit_verify: %s", Canon(r))
	}
}

func TestAuditTamperingIsDetected(t *testing.T) {
	e, state := newTestEngine(t, nil)
	token := issue(t, e, nil)["token"]
	for i := 0; i < 4; i++ {
		mustOK(t, e.Call("authorize", readRequest(token)))
	}
	log := filepath.Join(state, "audit.jsonl")
	original, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSuffix(string(original), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 records, got %d", len(lines))
	}
	n, head, err := VerifyAudit(log)
	if err != nil || n != 5 || !strings.Contains(lines[4], head) {
		t.Fatalf("VerifyAudit: %d %s %v", n, head, err)
	}
	tampered := map[string]string{
		"edited":    strings.Join([]string{lines[0], lines[1], strings.Replace(lines[2], `"effect":"allow"`, `"effect":"deny"`, 1), lines[3], lines[4]}, "\n"),
		"deleted":   strings.Join([]string{lines[0], lines[1], lines[3], lines[4]}, "\n"),
		"reordered": strings.Join([]string{lines[0], lines[2], lines[1], lines[3], lines[4]}, "\n"),
		"not json":  strings.Join([]string{lines[0], lines[1], "{", lines[3], lines[4]}, "\n"),
		"no first":  strings.Join(lines[1:], "\n"),
	}
	for name, text := range tampered {
		if err := os.WriteFile(log, []byte(text+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r := e.Call("audit_verify", map[string]any{})
		if errCode(r) != "audit_broken" || r["error"].(map[string]any)["rule"] != "DELEGATE-AUDIT-BROKEN" {
			t.Errorf("%s: %s", name, Canon(r))
		}
		// a new engine refuses to start on a broken log
		fresh, err := NewEngine(ConformanceConfig(specBundle(t), state, nil))
		if fresh != nil {
			fresh.Close()
		}
		if ee, ok := err.(*EngineError); !ok || ee.Code != "audit_broken" {
			t.Errorf("%s: NewEngine on a broken log: %v", name, err)
		}
	}
	// dropping the tail is not detectable from the file alone, but the count shows it
	if err := os.WriteFile(log, []byte(strings.Join(lines[:3], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.Call("audit_verify", map[string]any{}); r["records"] != int64(3) {
		t.Errorf("truncated tail: %s", Canon(r))
	}
}

// (5) One engine used from many goroutines, and two engines sharing a state
// directory. Run with -race.
func TestConcurrentUse(t *testing.T) {
	e, state := newTestEngine(t, nil)
	second, err := NewEngine(ConformanceConfig(specBundle(t), state, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	engines := []*Engine{e, second}

	const workers, rounds = 12, 12
	var wg sync.WaitGroup
	errs := make(chan string, workers*rounds*8)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			fail := func(format string, a ...any) { errs <- fmt.Sprintf("worker %d: ", w) + fmt.Sprintf(format, a...) }
			for r := 0; r < rounds; r++ {
				eng := engines[(w+r)%2]
				other := engines[(w+r+1)%2]
				root := eng.Call("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap(), "now": testNow})
				if root["ok"] != true {
					fail("issue: %s", Canon(root))
					continue
				}
				// 1 audit record each: issue, exchange, authorize, filter, revoke; the denied authorize is 1 more
				child := other.Call("exchange_token", map[string]any{"subject_token": root["token"], "actor": "refund-helper", "ttl": 60, "now": testNow})
				if child["ok"] != true {
					fail("exchange: %s", Canon(child))
					continue
				}
				if d := eng.Call("authorize", readRequest(child["token"])); d["effect"] != "allow" {
					fail("authorize: %s", Canon(d))
				}
				req := readRequest(root["token"])
				req["data"] = []any{map[string]any{"id": "c-1", "region": "EU", "ssn": "x"}, map[string]any{"id": "c-2", "region": "US"}}
				if f := other.Call("filter", req); f["effect"] != "allow" || f["rows_dropped"] != int64(1) || Canon(f["masked"]) != `["ssn"]` {
					fail("filter: %s", Canon(f))
				}
				if i := eng.Call("inspect_token", map[string]any{"token": child["token"], "now": testNow}); i["valid"] != true {
					fail("inspect: %s", Canon(i))
				}
				if rv := other.Call("revoke", map[string]any{"token_id": root["token_id"], "now": testNow}); rv["ok"] != true {
					fail("revoke: %s", Canon(rv))
				}
				// the other engine sees the revocation of the parent on its next call
				if d := eng.Call("authorize", readRequest(child["token"])); d["reason"] != "token_revoked" {
					fail("revoked child still accepted: %s", Canon(d))
				}
				if info := eng.Call("info", map[string]any{}); info["ok"] != true {
					fail("info: %s", Canon(info))
				}
				if tail := other.Call("audit_tail", map[string]any{"n": 3}); len(tail["records"].([]any)) != 3 {
					fail("audit_tail: %s", Canon(tail))
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
	for _, eng := range engines {
		v := eng.Call("audit_verify", map[string]any{})
		if v["ok"] != true || v["records"] != int64(workers*rounds*6) {
			t.Errorf("audit chain after concurrent use: %s (want %d records)", Canon(v), workers*rounds*6)
		}
	}
}

// A budget is never overspent, however many goroutines and engines spend at once.
func TestConcurrentSpendStaysWithinBudget(t *testing.T) {
	e, state := newTestEngine(t, nil)
	second, err := NewEngine(ConformanceConfig(specBundle(t), state, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	engines := []*Engine{e, second}
	// refund-small allows 3 calls a minute per (agent, user); a budget of 2500
	// allows 2 spends of 1000. Each token is hammered by 8 goroutines.
	budget := map[string]any{"actions": []any{"create"}, "resources": []any{"billing.refund/*"}, "budget": map[string]any{"EUR": int64(2500)}}
	for _, user := range []string{"alice", "bob", "erin"} {
		token := issue(t, e, map[string]any{"user": user, "cap": budget})["token"]
		var wg sync.WaitGroup
		var mu sync.Mutex
		reasons := map[string]int{}
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				d := engines[g%2].Call("authorize", spendRequest(token, 1000, testNow))
				mu.Lock()
				defer mu.Unlock()
				reasons[fmt.Sprint(d["reason"])]++
			}(g)
		}
		wg.Wait()
		if reasons["policy_permit"] != 2 || reasons["budget_exceeded"] != 6 {
			t.Errorf("%s: %v, want 2 permits and 6 budget_exceeded", user, reasons)
		}
	}
	raw, err := os.ReadFile(filepath.Join(state, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := ParseJSON(raw)
	for id, bucket := range parsed.(map[string]any)["ledger"].(map[string]any) {
		if bucket.(map[string]any)["EUR"] != int64(2000) {
			t.Errorf("ledger of %s: %s", id, Canon(bucket))
		}
	}
}

func TestSignedBundle(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle")
	copyDir(t, specBundle(t), bundle)
	private, public, err := Keygen()
	if err != nil {
		t.Fatal(err)
	}
	if id, err := KeyID(public); err != nil || len(id) != 16 {
		t.Fatalf("KeyID: %q %v", id, err)
	}
	signed, err := SignBundle(bundle, private)
	if err != nil {
		t.Fatal(err)
	}
	files, err := Manifest(bundle)
	if err != nil || VersionOf(files) != signed["version"] || len(files) != 4 {
		t.Fatalf("Manifest: %v %v", files, err)
	}
	e, err := NewEngine(map[string]any{"bundle_dir": bundle, "bundle_public_key": public})
	if err != nil {
		t.Fatal(err)
	}
	info := e.Call("info", map[string]any{})
	e.Close()
	if info["bundle_signed_by"] != signed["key_id"] || info["policy_version"] != signed["version"] {
		t.Errorf("info: %s", Canon(info))
	}
	// CRLF line endings do not change the version
	entities, _ := os.ReadFile(filepath.Join(bundle, "entities.json"))
	if err := os.WriteFile(filepath.Join(bundle, "entities.json"), []byte(strings.ReplaceAll(string(entities), "\n", "\r\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := LoadBundle(bundle, public); err != nil || b.Version != signed["version"] {
		t.Errorf("CRLF checkout: %v", err)
	}
	// a changed file, another key, a missing signature
	if err := os.WriteFile(filepath.Join(bundle, "entities.json"), []byte(strings.Replace(string(entities), `"region": "EU"`, `"region": "US"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(bundle, public); err == nil || err.(*EngineError).Code != "bundle_signature" {
		t.Errorf("a changed file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "entities.json"), entities, 0o600); err != nil {
		t.Fatal(err)
	}
	_, otherPublic, _ := Keygen()
	if _, err := LoadBundle(bundle, otherPublic); err == nil || err.(*EngineError).Code != "bundle_signature" {
		t.Errorf("another key: %v", err)
	}
	if err := os.Remove(filepath.Join(bundle, "bundle.sig.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(bundle, public); err == nil || err.(*EngineError).Code != "bundle_unsigned" {
		t.Errorf("no signature: %v", err)
	}
	// an edited .cedar source without recompiling
	cedar := filepath.Join(bundle, "policies", "extra.cedar")
	if err := os.WriteFile(cedar, []byte("permit(principal, action, resource);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(bundle, ""); err == nil || err.(*EngineError).Code != "bundle_stale" {
		t.Errorf("a stale bundle: %v", err)
	}
	// reload keeps the old bundle when the new one does not load
	if err := os.Remove(cedar); err != nil {
		t.Fatal(err)
	}
	live, err := NewEngine(map[string]any{"bundle_dir": bundle})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	before := live.Call("info", map[string]any{})["policy_version"]
	if err := os.WriteFile(filepath.Join(bundle, "roles.json"), []byte(`{"roles": {"r": {"members": [{"type": "Group", "id": "g"}], "cap": {}, "max_tll": 5}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := live.Call("reload", map[string]any{}); errCode(r) != "roles_parse" {
		t.Errorf("reload of a bundle with a misspelt role key: %s", Canon(r))
	}
	if after := live.Call("info", map[string]any{})["policy_version"]; after != before {
		t.Error("a failed reload must leave the old bundle in force")
	}
}

func copyDir(t testing.TB, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), raw, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCedarLongsAre64Bit(t *testing.T) {
	store, _ := NewStore(nil)
	eval := func(expr string, ctx string) (any, error) {
		c, err := fromJSON(mustParse(t, ctx))
		if err != nil {
			return nil, err
		}
		return evaluate(mustParse(t, expr), &Env{Context: c.(map[string]any), Store: store})
	}
	bin := func(op, l, r string) string {
		return fmt.Sprintf(`{%q:{"left":{".":{"left":{"Var":"context"},"attr":"a"}},"right":{".":{"left":{"Var":"context"},"attr":"b"}}}}`, op)
	}
	const max, min = "9223372036854775807", "-9223372036854775808"
	cases := []struct {
		op, a, b string
		want     any // nil: overflow
	}{
		{"+", max, "0", int64(9223372036854775807)}, {"+", max, "1", nil}, {"+", min, "-1", nil}, {"+", max, min, int64(-1)},
		{"-", min, "1", nil}, {"-", max, "-1", nil}, {"-", min, min, int64(0)}, {"-", "0", min, nil}, {"-", "-1", min, int64(9223372036854775807)},
		{"*", max, "2", nil}, {"*", min, "-1", nil}, {"*", "-1", min, nil}, {"*", min, "1", int64(-9223372036854775808)}, {"*", "0", min, int64(0)},
		{"*", "3037000500", "3037000500", nil}, {"*", "3037000499", "3037000499", int64(9223372030926249001)}, {"*", "4294967296", "-2147483648", int64(-9223372036854775808)},
		{"<", min, max, true}, {">=", max, max, true}, {"==", max, max, true}, {"!=", max, min, true},
	}
	for _, c := range cases {
		got, err := eval(bin(c.op, c.a, c.b), fmt.Sprintf(`{"a":%s,"b":%s}`, c.a, c.b))
		if c.want == nil {
			if err == nil {
				t.Errorf("%s %s %s = %v, want an overflow error", c.a, c.op, c.b, got)
			}
		} else if err != nil || got != c.want {
			t.Errorf("%s %s %s = %v (%v), want %v", c.a, c.op, c.b, got, err, c.want)
		}
	}
	if got, err := eval(`{"neg":{"arg":{".":{"left":{"Var":"context"},"attr":"a"}}}}`, `{"a":`+min+`}`); err == nil {
		t.Errorf("-(%s) = %v, want an overflow error", min, got)
	}
	if got, err := eval(`{"neg":{"arg":{".":{"left":{"Var":"context"},"attr":"a"}}}}`, `{"a":`+max+`}`); err != nil || got != int64(-9223372036854775807) {
		t.Errorf("-(%s) = %v (%v)", max, got, err)
	}
	for _, ctx := range []string{`{"a":9223372036854775808}`, `{"a":1.0}`, `{"a":null}`, `{"a":[1,[2.5]]}`, `{"a":{"__extn":{}}}`, `{"a":{"__entity":{"type":"T"}}}`} {
		if _, err := fromJSON(mustParse(t, ctx)); err == nil {
			t.Errorf("%s is not a Cedar value", ctx)
		}
	}
}
