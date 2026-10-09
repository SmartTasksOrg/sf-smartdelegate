package smartdelegate

import (
	"bufio"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// startReferenceDaemon runs `python3 -m sf_smartdelegate serve` on a free port
// with its own state directory and returns its URL.
func startReferenceDaemon(t *testing.T, extra map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	cfg := ConformanceConfig(specBundle(t), filepath.Join(dir, "state"), extra)
	cfg["admin_key"], cfg["pep_key"] = testAdmin, testPep
	path := filepath.Join(dir, "smartdelegate.json")
	writeJSONFile(t, path, cfg)
	cmd := exec.Command("python3", "-m", "sf_smartdelegate", "serve", "--config", path, "--listen", "127.0.0.1:0")
	cmd.Env = pythonEnv(t)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	lineCh := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stderr).ReadString('\n')
		lineCh <- line
	}()
	select {
	case line := <-lineCh:
		m := regexp.MustCompile(`http://\S+`).FindString(line)
		if m == "" {
			t.Fatalf("the reference daemon did not start: %q", line)
		}
		return m
	case <-time.After(30 * time.Second):
		t.Fatal("the reference daemon printed no startup line")
	}
	return ""
}

// This port's client against the reference's daemon: the conformance vectors.
func TestInteropClientAgainstReferenceDaemon(t *testing.T) {
	needPython(t)
	if testing.Short() {
		t.Skip("starts one reference daemon per case; skipped with -short")
	}
	cases, steps, failed := 0, 0, 0
	for _, s := range vectorSuites(t) {
		for _, tc := range s.Cases {
			url := startReferenceDaemon(t, s.Config)
			res := RunCase(NewClient(url, testPep, testAdmin), tc)
			cases++
			steps += countSteps(tc)
			if !res.Passed {
				failed++
				t.Errorf("%s: %s: %v", s.File, res.Name, res.Failures)
			}
		}
	}
	if cases != 78 || steps != 327 {
		t.Errorf("expected 78 cases and 327 steps, ran %d cases and %d steps", cases, steps)
	}
	t.Logf("conformance, Go client against the reference daemon: %d cases (%d steps), %d failed", cases, steps, failed)
}

// The same raw HTTP requests to this port's daemon and to the reference's:
// status code and body must agree (keys, routes, bodies, limits).
func TestInteropDaemonBehaviour(t *testing.T) {
	needPython(t)
	theirs := startReferenceDaemon(t, nil)
	srv, _ := startServer(t, nil)
	mine := srv.URL

	type request struct {
		method, path, key string
		body              string
		headers           []string
	}
	issueBody := string(MarshalJSON(map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap(), "now": testNow}))
	authz := func(token string) string { return string(MarshalJSON(readRequest(token))) }
	var requests []request
	for _, key := range []string{"", testPep, testAdmin, "wrong", testAdmin + " ", " " + testPep, testPep + "x", "Bearer " + testPep} {
		for _, r := range [][3]string{
			{"GET", "/healthz", ""}, {"POST", "/healthz", "{}"}, {"GET", "/v1/info", ""}, {"POST", "/v1/info", "{}"}, {"GET", "/v1/authorize", ""},
			{"POST", "/v1/authorize", "{}"}, {"POST", "/v1/authorize", authz("junk")}, {"POST", "/v1/filter", authz("junk")}, {"POST", "/v1/explain", authz("junk")},
			{"POST", "/v1/obligations/apply", `{"obligations":{"fields":{"allow":["a"]}},"data":{"a":1,"b":2}}`}, {"POST", "/v1/token/inspect", `{"token":"x"}`},
			{"POST", "/v1/token", issueBody}, {"POST", "/v1/token", `{"subject_token":"junk","actor":"refund-helper"}`},
			{"POST", "/v1/token", `{"id_token":"junk","user":"alice","agent":"support-bot","cap":{}}`}, {"POST", "/v1/token", `{}`}, {"POST", "/v1/token", `[]`},
			{"POST", "/v1/token", `{"subject_token":null}`}, {"POST", "/v1/token", `{"id_token":null,"user":"alice","agent":"ghost","cap":{}}`},
			{"GET", "/v1/token", ""}, {"POST", "/v1/admin/revoke", `{"token_id":"t-1"}`}, {"POST", "/v1/admin/revoke", `{"user":"alice","by":"hr","now":1700000000}`}, {"POST", "/v1/admin/revoke", `{"user":"","token_id":"t-1"}`}, {"POST", "/v1/admin/approve", `{"approval_id":"x","by":"bob"}`},
			{"GET", "/v1/admin/approvals", ""}, {"POST", "/v1/admin/approvals", "{}"}, {"GET", "/v1/admin/audit/verify", ""}, {"GET", "/v1/admin/audit/tail", ""},
			{"GET", "/v1/admin/audit/tail?n=1", ""}, {"GET", "/v1/admin/audit/tail?n=0", ""}, {"GET", "/v1/admin/audit/tail?n=x&n=1", ""}, {"GET", "/v1/admin/audit/tail?m=1&n=2", ""},
			{"GET", "/v1/admin/audit/tail?n=-1", ""}, {"GET", "/v1/admin/audit/tail?n=1.5", ""}, {"GET", "/v1/admin/audit/tail?n=99999999999999999999999999", ""},
			{"GET", "/v1/admin/audit/tail?n", ""}, {"GET", "/v1/admin/audit/tail?n=", ""}, {"GET", "/v1/admin/audit/tail?N=1", ""}, {"GET", "/v1/admin/audit/tail?x=n=1", ""},
			{"GET", "/v1/admin/audit/tail/?n=1", ""}, {"GET", "/", ""}, {"GET", "/v1", ""}, {"GET", "/v1/info/", ""}, {"GET", "/v1/info?x=1", ""}, {"GET", "//v1/info", ""}, {"GET", "///v1//info", ""}, {"GET", "//v1/admin/audit/tail?n=1", ""}, {"GET", "/v1/info?", ""}, {"GET", "/v1/info#x", ""},
			{"GET", "/v1/../v1/info", ""}, {"GET", "/V1/INFO", ""}, {"GET", "/v1/info%3Fx", ""}, {"GET", "/v1/%69nfo", ""}, {"POST", "/v1/nowhere", "{"}, {"POST", "/v1/nowhere", "{}"},
			{"POST", "/v1/authorize", "{"}, {"POST", "/v1/authorize", ""}, {"POST", "/v1/authorize", "  \n\t "}, {"POST", "/v1/authorize", "\x0b"}, {"POST", "/v1/authorize", "[1]"},
			{"POST", "/v1/authorize", "null"}, {"POST", "/v1/authorize", `"str"`}, {"POST", "/v1/authorize", "5"}, {"POST", "/v1/authorize", "\xef\xbb\xbf{}"},
			{"POST", "/v1/authorize", "\xff\xfe"}, {"POST", "/v1/authorize", `{"a":1}{"b":2}`}, {"POST", "/v1/authorize", `{"token":"x","action":"read","resource":{"path":"crm.customer"},"context":{"n":1.5}}`},
			{"POST", "/v1/authorize", `{"token":"x","action":"read","resource":{"path":"crm.customer"},"context":{"n":NaN}}`},
			{"POST", "/v1/authorize", strings.Repeat("[", 300) + strings.Repeat("]", 300)}, {"POST", "/v1/authorize", strings.Repeat("[", 100000) + strings.Repeat("]", 100000)},
			{"POST", "/v1/authorize", `{"token":"` + strings.Repeat("a", 1<<20) + `"}`}, {"POST", "/v1/admin/reload", ""},
		} {
			requests = append(requests, request{method: r[0], path: r[1], key: key, body: r[2]})
		}
	}
	requests = append(requests,
		request{method: "POST", path: "/v1/authorize", body: authz("junk"), headers: []string{"Authorization", "Basic " + testPep}},
		request{method: "POST", path: "/v1/authorize", body: authz("junk"), headers: []string{"Authorization", "bearer " + testPep}},
		request{method: "POST", path: "/v1/authorize", body: authz("junk"), headers: []string{"Authorization", "Bearer  \t" + testPep + " "}},
		request{method: "POST", path: "/v1/authorize", body: authz("junk"), headers: []string{"Authorization", "Bearer" + testPep}},
		request{method: "POST", path: "/v1/authorize", body: authz("junk"), headers: []string{"X-Api-Key", testPep}},
		request{method: "POST", path: "/v1/authorize", body: authz("junk"), key: testPep, headers: []string{"Content-Type", "text/plain"}},
		request{method: "GET", path: "/v1/info", key: testPep, body: `{"ignored":true}`},
	)
	mismatches := 0
	statuses := map[int]int{}
	for _, r := range requests {
		var body []byte
		if r.method == "POST" || r.body != "" {
			body = []byte(r.body)
		}
		codeA, bodyA, typeA := do(t, r.method, mine+r.path, r.key, body, r.headers...)
		codeB, bodyB, typeB := do(t, r.method, theirs+r.path, r.key, body, r.headers...)
		statuses[codeA]++
		for _, m := range []map[string]any{bodyA, bodyB} {
			delete(m, "token")
			delete(m, "token_id")
		}
		a, b := Canon(scrub(bodyA, nil)), Canon(scrub(bodyB, nil))
		if strings.Contains(r.path, "/info") || r.path == "/v1/admin/reload" {
			for _, m := range []map[string]any{bodyA, bodyB} {
				delete(m, "key_id")
				delete(m, "public_key")
			}
			a, b = Canon(scrub(bodyA, nil)), Canon(scrub(bodyB, nil))
		}
		if strings.Contains(r.path, "audit/tail") {
			// the two logs hold different records; compare how many came back
			ra, _ := bodyA["records"].([]any)
			rb, _ := bodyB["records"].([]any)
			a, b = Canon(map[string]any{"ok": bodyA["ok"], "error": scrub(bodyA["error"], nil), "records": len(ra)}), Canon(map[string]any{"ok": bodyB["ok"], "error": scrub(bodyB["error"], nil), "records": len(rb)})
		}
		if codeA != codeB || a != b || typeA != typeB {
			mismatches++
			if mismatches <= 15 {
				t.Errorf("%s %s (key %q, body %.80q, headers %q)\n  go        %d %s %.600s\n  reference %d %s %.600s", r.method, r.path, r.key, r.body, r.headers, codeA, typeA, a, codeB, typeB, b)
			}
		}
	}
	for _, code := range []int{200, 400, 401, 404} {
		if statuses[code] == 0 {
			t.Errorf("no request was answered with %d: %v", code, statuses)
		}
	}
	t.Logf("daemon behaviour: %d requests %v, %d mismatches", len(requests), statuses, mismatches)
}
