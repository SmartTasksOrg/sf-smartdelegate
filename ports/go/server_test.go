package smartdelegate

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

const (
	testAdmin = "admin-key-for-tests-0123456789"
	testPep   = "pep-key-for-tests-0123456789"
)

func startServer(t *testing.T, extra map[string]any) (*Server, *Engine) {
	t.Helper()
	e, _ := newTestEngine(t, extra)
	srv, err := Listen(e, "127.0.0.1:0", testAdmin, testPep)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, e
}

func do(t *testing.T, method, url, key string, body []byte, headers ...string) (int, map[string]any, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	v, _ := ParseJSON(raw)
	m, _ := v.(map[string]any)
	return resp.StatusCode, m, resp.Header.Get("Content-Type")
}

func TestDaemonKeysAndStatusCodes(t *testing.T) {
	srv, _ := startServer(t, nil)
	u := srv.URL
	issueBody := MarshalJSON(map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap(), "now": testNow})

	// /healthz needs no key
	if code, body, ctype := do(t, "GET", u+"/healthz", "", nil); code != 200 || body["ok"] != true || ctype != "application/json" {
		t.Errorf("healthz: %d %v %s", code, body, ctype)
	}
	// issuing a root token for a named user needs the admin key
	for _, key := range []string{"", testPep, "wrong", testAdmin + "x", testAdmin[:len(testAdmin)-1]} {
		if code, body, _ := do(t, "POST", u+"/v1/token", key, issueBody); code != 401 || errCode(body) != "unauthorized" {
			t.Errorf("issue with key %q: %d %v", key, code, body)
		}
	}
	code, issued, _ := do(t, "POST", u+"/v1/token", testAdmin, issueBody)
	if code != 200 || issued["ok"] != true {
		t.Fatalf("issue with the admin key: %d %v", code, issued)
	}
	token := issued["token"].(string)
	authz := MarshalJSON(readRequest(token))

	// pep routes: the pep key or the admin key
	for _, c := range []struct {
		key  string
		want int
	}{{"", 401}, {"wrong", 401}, {testPep, 200}, {testAdmin, 200}, {"  " + testPep + "  ", 200}} {
		req, _ := http.NewRequest("POST", u+"/v1/authorize", bytes.NewReader(authz))
		if c.key != "" {
			req.Header.Set("Authorization", "Bearer "+c.key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("authorize with key %q: %d, want %d", c.key, resp.StatusCode, c.want)
		}
	}
	// not a bearer scheme
	if code, _, _ := do(t, "POST", u+"/v1/authorize", "", authz, "Authorization", "Basic "+testPep); code != 401 {
		t.Errorf("Basic auth: %d", code)
	}
	if code, _, _ := do(t, "POST", u+"/v1/authorize", "", authz, "Authorization", "bearer "+testPep); code != 401 {
		t.Errorf("lower-case scheme: %d", code)
	}
	// admin routes: the admin key only
	for _, r := range [][2]string{{"GET", "/v1/admin/approvals"}, {"GET", "/v1/admin/audit/verify"}, {"GET", "/v1/admin/audit/tail"},
		{"POST", "/v1/admin/revoke"}, {"POST", "/v1/admin/approve"}, {"POST", "/v1/admin/reload"}} {
		if code, _, _ := do(t, r[0], u+r[1], testPep, nil); code != 401 {
			t.Errorf("%s %s with the pep key: %d", r[0], r[1], code)
		}
		if code, _, _ := do(t, r[0], u+r[1], testAdmin, nil); code == 401 || code == 404 {
			t.Errorf("%s %s with the admin key: %d", r[0], r[1], code)
		}
	}
	for _, r := range [][2]string{{"GET", "/v1/info"}, {"POST", "/v1/authorize"}, {"POST", "/v1/filter"}, {"POST", "/v1/explain"},
		{"POST", "/v1/obligations/apply"}, {"POST", "/v1/token/inspect"}} {
		if code, _, _ := do(t, r[0], u+r[1], "", nil); code != 401 {
			t.Errorf("%s %s without a key: %d", r[0], r[1], code)
		}
	}
	// token exchange needs no key: the subject token is the authority
	exch := MarshalJSON(map[string]any{"subject_token": token, "actor": "refund-helper", "ttl": 60, "now": testNow})
	if code, body, _ := do(t, "POST", u+"/v1/token", "", exch); code != 200 || body["ok"] != true {
		t.Errorf("exchange without a key: %d %v", code, body)
	}
	if code, body, _ := do(t, "POST", u+"/v1/token", "", MarshalJSON(map[string]any{"subject_token": "junk", "actor": "refund-helper"})); code != 400 || errCode(body) != "token_invalid" {
		t.Errorf("exchange of a bad token: %d %v", code, body)
	}
	// an engine error is 400 with the engine's result; a deny is 200
	if code, body, _ := do(t, "POST", u+"/v1/authorize", testPep, []byte(`{}`)); code != 400 || errCode(body) != "invalid_input" || body["error"].(map[string]any)["rule"] != "DELEGATE-INVALID-INPUT" {
		t.Errorf("authorize {}: %d %v", code, body)
	}
	if code, body, _ := do(t, "POST", u+"/v1/authorize", testPep, MarshalJSON(readRequest("junk"))); code != 200 || body["effect"] != "deny" {
		t.Errorf("a deny: %d %v", code, body)
	}
	// bodies
	if code, body, _ := do(t, "POST", u+"/v1/authorize", testPep, []byte(`{"token":`)); code != 400 || errCode(body) != "invalid_input" || body["error"].(map[string]any)["message"] != "body is not JSON" {
		t.Errorf("a body that is not JSON: %d %v", code, body)
	}
	if code, body, _ := do(t, "POST", u+"/v1/nowhere", "", []byte(`{"token":`)); code != 400 {
		t.Errorf("the body is read before the route is looked up: %d %v", code, body)
	}
	if code, body, _ := do(t, "POST", u+"/v1/authorize", testPep, []byte(`[1,2]`)); code != 400 || errCode(body) != "invalid_input" {
		t.Errorf("a body that is not an object: %d %v", code, body)
	}
	if code, body, _ := do(t, "POST", u+"/v1/token/inspect", testPep, []byte("  \n ")); code != 400 || errCode(body) != "invalid_input" {
		t.Errorf("a blank body is {}: %d %v", code, body)
	}
	if code, body, _ := do(t, "POST", u+"/v1/token/inspect", testPep, append([]byte("\xef\xbb\xbf"), MarshalJSON(map[string]any{"token": token, "now": testNow})...)); code != 200 || body["valid"] != true {
		t.Errorf("a body with a byte order mark: %d %v", code, body)
	}
	huge := append([]byte(`{"token":"`), bytes.Repeat([]byte("a"), MaxBody)...)
	huge = append(huge, []byte(`"}`)...)
	if code, body, _ := do(t, "POST", u+"/v1/authorize", testPep, huge); code != 400 || body["error"].(map[string]any)["message"] != "request body is too large" {
		t.Errorf("a body over the limit: %d %v", code, body)
	}
	deep := []byte(strings.Repeat("[", 5000) + strings.Repeat("]", 5000))
	if code, body, _ := do(t, "POST", u+"/v1/authorize", testPep, deep); code != 400 || errCode(body) != "invalid_input" {
		t.Errorf("a deeply nested body: %d %v", code, body)
	}
	// unknown routes and methods
	for _, r := range [][2]string{{"GET", "/"}, {"GET", "/v1/authorize"}, {"POST", "/v1/info"}, {"GET", "/v1/token"}, {"POST", "/v1/authorize/"}, {"GET", "/v1/info/x"}, {"GET", "/v1//info"}} {
		if code, body, _ := do(t, r[0], u+r[1], testAdmin, nil); code != 404 || errCode(body) != "not_found" {
			t.Errorf("%s %s: %d %v", r[0], r[1], code, body)
		}
	}
	if code, _, _ := do(t, "DELETE", u+"/v1/info", testAdmin, nil); code != 501 {
		t.Errorf("DELETE: %d", code)
	}
	if code, body, _ := do(t, "GET", u+"/v1/info?x=1", testPep, nil); code != 200 || body["implementation"] != "go" {
		t.Errorf("a query string does not change the route: %d %v", code, body)
	}
	// audit tail: ?n=
	_, all, _ := do(t, "GET", u+"/v1/admin/audit/tail?n=1000", testAdmin, nil)
	total := len(all["records"].([]any))
	if total < 3 || total > 20 {
		t.Fatalf("expected between 3 and 20 audit records by now, got %d", total)
	}
	for query, want := range map[string]int{"": total, "?n=1": 1, "?n=2": 2, "?n=x": total, "?n=-1": total, "?m=1&n=2": 2, "?n=1&n=3": 1,
		"?n=99999999999999999999999": total, "?n=0": 0, "?x=n=1": total} {
		code, body, _ := do(t, "GET", u+"/v1/admin/audit/tail"+query, testAdmin, nil)
		records, _ := body["records"].([]any)
		if code != 200 || len(records) != want {
			t.Errorf("audit tail %q: %d, %d records, want %d", query, code, len(records), want)
		}
	}
}

// With an ID token, /v1/token needs no key and ignores `user` (and the engine ignores `groups`).
func TestDaemonIDTokenPath(t *testing.T) {
	var oidc *VectorSuite
	for _, s := range vectorSuites(t) {
		if s.File == "08_oidc.json" {
			s := s
			oidc = &s
		}
	}
	if oidc == nil {
		t.Fatal("08_oidc.json not found")
	}
	// the first issue_token step with an id_token that the vectors expect to succeed
	var input map[string]any
	for _, tc := range oidc.Cases {
		for _, s := range tc["steps"].([]any) {
			step := s.(map[string]any)
			in, _ := step["input"].(map[string]any)
			expect, _ := step["expect"].(map[string]any)
			if _, has := in["id_token"].(string); has && step["op"] == "issue_token" && expect["ok"] == true && input == nil {
				input = in
			}
		}
	}
	if input == nil {
		t.Fatal("no successful id_token step in 08_oidc.json")
	}
	srv, e := startServer(t, oidc.Config)
	direct := mustOK(t, e.Call("issue_token", input))
	body := map[string]any{}
	for k, v := range input {
		body[k] = v
	}
	body["user"] = "somebody-else"
	if r := e.Call("issue_token", body); errCode(r) != "id_token_invalid" {
		t.Fatalf("in-process, a different `user` is refused: %s", Canon(r))
	}
	code, viaREST, _ := do(t, "POST", srv.URL+"/v1/token", "", MarshalJSON(body))
	if code != 200 || viaREST["user"] != direct["user"] {
		t.Errorf("over REST `user` is ignored and no key is needed: %d %s", code, Canon(viaREST))
	}
	body["id_token"] = "not.a.token"
	if code, r, _ := do(t, "POST", srv.URL+"/v1/token", "", MarshalJSON(body)); code != 400 || errCode(r) != "id_token_invalid" {
		t.Errorf("a bad ID token: %d %s", code, Canon(r))
	}
	// the client sends no key with an ID token, and the admin key otherwise
	noKeys := NewClient(srv.URL, "", "")
	if r := noKeys.Call("issue_token", input); r["ok"] != true {
		t.Errorf("client without keys, with an ID token: %s", Canon(r))
	}
	if r := noKeys.Call("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap()}); errCode(r) != "unauthorized" {
		t.Errorf("client without keys, without an ID token: %s", Canon(r))
	}
}

func TestClient(t *testing.T) {
	srv, _ := startServer(t, nil)
	admin := NewClient(srv.URL+"/", "", testAdmin) // the admin key also serves as the pep key
	token := issue(t, admin, nil)["token"]
	if r := admin.Call("authorize", readRequest(token)); r["effect"] != "allow" {
		t.Errorf("authorize: %s", Canon(r))
	}
	pep := NewClient(srv.URL, testPep, "")
	if r := pep.Call("authorize", readRequest(token)); r["effect"] != "allow" {
		t.Errorf("authorize with the pep key: %s", Canon(r))
	}
	if r := pep.Call("revoke", map[string]any{"token": token}); errCode(r) != "unauthorized" {
		t.Errorf("revoke with the pep key: %s", Canon(r))
	}
	if r := pep.Call("nonsense", map[string]any{}); errCode(r) != "unknown_op" {
		t.Errorf("unknown op: %s", Canon(r))
	}
	for n, want := range map[any]int{1: 1, int64(2): 2, nil: 3} {
		in := map[string]any{}
		if n != nil {
			in["n"] = n
		}
		if r := admin.Call("audit_tail", in); len(r["records"].([]any)) != want {
			t.Errorf("audit_tail n=%v: %s", n, Canon(r))
		}
	}
	if r := admin.Call("audit_tail", map[string]any{"n": "1&x=2"}); r["ok"] != false {
		t.Errorf("audit_tail with a string n: %s", Canon(r))
	}
	// integers survive the round trip exactly
	req := readRequest(token)
	req["data"] = map[string]any{"id": int64(9007199254740993), "region": "EU"}
	if r := pep.Call("filter", req); r["data"].(map[string]any)["id"] != int64(9007199254740993) {
		t.Errorf("an integer beyond 2^53 over REST: %s", Canon(r))
	}
	// an unreachable daemon is an error result, never an allow
	_ = srv.Close()
	if r := pep.Call("authorize", readRequest(token)); r["ok"] != false || errCode(r) != "daemon_unreachable" || r["effect"] != nil {
		t.Errorf("unreachable daemon: %s", Canon(r))
	}
}

func TestListen(t *testing.T) {
	e, _ := newTestEngine(t, nil)
	for _, keys := range [][2]string{{"", ""}, {"short", testPep}, {testAdmin, "short"}, {testAdmin, ""}} {
		if srv, err := Listen(e, "127.0.0.1:0", keys[0], keys[1]); err == nil {
			_ = srv.Close()
			t.Errorf("Listen with keys %q must fail", keys)
		}
	}
	for text, want := range map[string]string{"127.0.0.1:8181": "127.0.0.1:8181", ":0": "127.0.0.1:0", "0": "127.0.0.1:0", "localhost:1": "localhost:1", "[::1]:9": "[::1]:9"} {
		if got, err := ListenAddress(text); err != nil || got != want {
			t.Errorf("ListenAddress(%q) = %q, %v", text, got, err)
		}
	}
	for _, text := range []string{"", "host", "127.0.0.1:", "127.0.0.1:http", "1:99999"} {
		if got, err := ListenAddress(text); err == nil {
			t.Errorf("ListenAddress(%q) = %q, want an error", text, got)
		}
	}
}
