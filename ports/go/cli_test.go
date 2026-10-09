package smartdelegate

import (
	"bufio"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// cliSetup writes a config file (with paths relative to it) and a cap file.
func cliSetup(t *testing.T, extra map[string]any) (dir, cfg, capFile string) {
	t.Helper()
	dir = t.TempDir()
	copyDir(t, specBundle(t), filepath.Join(dir, "conf", "bundle"))
	c := map[string]any{"bundle_dir": "bundle", "state_dir": "../state", "allow_test_clock": true, "max_depth": 3}
	for k, v := range extra {
		c[k] = v
	}
	cfg = filepath.Join(dir, "conf", "smartdelegate.json")
	writeJSONFile(t, cfg, c)
	capFile = filepath.Join(dir, "cap.json")
	writeJSONFile(t, capFile, fullCap())
	return dir, cfg, capFile
}

func TestCLI(t *testing.T) {
	dir, cfg, capFile := cliSetup(t, nil)

	// paths in the config file are relative to the file, not to the working directory
	info := gocli(t, "info", "--config", cfg)
	if info.code != 0 || info.json(t)["implementation"] != "go" || info.json(t)["version"] != "0.3.0" {
		t.Fatalf("info: %d %s %s", info.code, info.stdout, info.stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "signing_key.pk8.b64")); err != nil {
		t.Errorf("state_dir must resolve relative to the config file: %v", err)
	}
	// the same through SMARTDELEGATE_CONFIG, and through ./smartdelegate.json
	viaEnv := runCmd(t, cleanEnv("SMARTDELEGATE_CONFIG="+cfg), dir, nil, goCLI(t), "info")
	viaCwd := runCmd(t, cleanEnv(), filepath.Dir(cfg), nil, goCLI(t), "info")
	for _, r := range []cliResult{viaEnv, viaCwd} {
		if r.code != 0 || r.json(t)["key_id"] != info.json(t)["key_id"] {
			t.Errorf("config lookup: %d %s %s", r.code, r.stdout, r.stderr)
		}
	}
	if r := runCmd(t, cleanEnv(), dir, nil, goCLI(t), "info"); r.code != 1 || !strings.Contains(r.stderr, "smartdelegate: no bundle") {
		t.Errorf("no config: %d %q", r.code, r.stderr)
	}
	// --bundle and --state override the file; --shadow sets the mode
	other := filepath.Join(dir, "other-state")
	over := gocli(t, "info", "--config", cfg, "--state", other, "--bundle", specBundle(t), "--shadow")
	if over.code != 0 || over.json(t)["mode"] != "shadow" || over.json(t)["key_id"] == info.json(t)["key_id"] {
		t.Errorf("overrides: %d %s", over.code, over.stdout)
	}

	// token issue --raw, then the exit codes: 0 allow, 2 deny, 1 error
	issued := gocli(t, "token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "@"+capFile, "--ttl", "600", "--raw", "--config", cfg)
	if issued.code != 0 || strings.Count(issued.stdout, ".") != 2 {
		t.Fatalf("token issue --raw: %d %q %q", issued.code, issued.stdout, issued.stderr)
	}
	token := issued.stdout
	allow := gocli(t, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-1", "--config", cfg)
	if allow.code != 0 || allow.json(t)["effect"] != "allow" {
		t.Errorf("allow: %d %s", allow.code, allow.stdout)
	}
	deny := gocli(t, "authorize", "--token", token, "--action", "delete", "--resource", "crm.customer/c-1", "--config", cfg)
	if deny.code != 2 || deny.json(t)["reason"] != "capability_action" {
		t.Errorf("deny: %d %s", deny.code, deny.stdout)
	}
	bad := gocli(t, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-1", "--context", `{"x":1.5}`, "--config", cfg)
	if bad.code != 1 || errCode(bad.json(t)) != "invalid_context" {
		t.Errorf("error: %d %s", bad.code, bad.stdout)
	}
	if r := gocli(t, "authorize", "--action", "read", "--config", cfg); r.code != 1 || !strings.Contains(r.stderr, "--resource is required") {
		t.Errorf("missing flag: %d %q", r.code, r.stderr)
	}
	if r := gocli(t, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer", "--context", "{", "--config", cfg); r.code != 1 || !strings.Contains(r.stderr, "not valid JSON") {
		t.Errorf("bad JSON flag: %d %q", r.code, r.stderr)
	}
	// --data makes it a filter; --strict denies instead of dropping; --dry-run; --attrs; explain
	filter := gocli(t, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-1", "--data", `{"id":"c-1","ssn":"1","region":"EU"}`, "--config", cfg)
	if filter.code != 0 || Canon(filter.json(t)["data"]) != `{"id":"c-1","region":"EU"}` {
		t.Errorf("filter: %d %s", filter.code, filter.stdout)
	}
	strict := gocli(t, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-1", "--data", `{"ssn":"1","region":"EU"}`, "--strict", "--dry-run", "--config", cfg)
	if strict.code != 2 || strict.json(t)["reason"] != "field_denied" {
		t.Errorf("strict: %d %s", strict.code, strict.stdout)
	}
	tenant := gocli(t, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-1", "--attrs", `{"tenant":"t1","n":1.5}`, "--config", cfg)
	if tenant.code != 1 || errCode(tenant.json(t)) != "invalid_input" {
		t.Errorf("attrs: %d %s", tenant.code, tenant.stdout)
	}
	explain := gocli(t, "explain", "--token", token, "--action", "read", "--resource", "crm.customer/c-1", "--config", cfg)
	if trace, _ := explain.json(t)["explain"].([]any); explain.code != 0 || len(trace) < 3 {
		t.Errorf("explain: %d %s", explain.code, explain.stdout)
	}

	// exchange, inspect, role and groups, revoke
	child := gocli(t, "token", "exchange", "--token", token, "--actor", "refund-helper", "--ttl=300", "--cap", `{"actions":["read"],"resources":["crm.customer/c-1"]}`, "--config", cfg)
	if child.code != 0 || Canon(child.json(t)["chain"]) != `["support-bot","refund-helper"]` {
		t.Fatalf("token exchange: %d %s %s", child.code, child.stdout, child.stderr)
	}
	inspect := gocli(t, "token", "inspect", "--token", child.json(t)["token"].(string), "--config", cfg)
	if inspect.code != 0 || inspect.json(t)["valid"] != true {
		t.Errorf("token inspect: %d %s", inspect.code, inspect.stdout)
	}
	role := gocli(t, "token", "issue", "--user", "dave", "--agent", "support-bot", "--role", "supervisor", "--groups", "supervisors,,support,nope", "--task", "escalation-4", "--tenant", "t1", "--config", cfg)
	if role.code != 0 || role.json(t)["role"] != "supervisor" || role.json(t)["expires_in"] != int64(300) {
		t.Errorf("token issue --role --groups: %d %s", role.code, role.stdout)
	}
	if r := gocli(t, "token", "issue", "--user", "dave", "--agent", "support-bot", "--role", "supervisor", "--task", "escalation-4", "--config", cfg); r.code != 1 || errCode(r.json(t)) != "role_not_held" {
		t.Errorf("a role the user does not hold: %d %s", r.code, r.stdout)
	}
	if r := gocli(t, "token", "issue", "--user", "alice", "--agent", "support-bot", "--config", cfg); r.code != 1 || !strings.Contains(r.stderr, "--cap JSON or --role NAME is required") {
		t.Errorf("neither --cap nor --role: %d %q", r.code, r.stderr)
	}
	if r := gocli(t, "token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "@"+capFile, "--ttl", "soon", "--config", cfg); r.code != 1 || !strings.Contains(r.stderr, "--ttl") {
		t.Errorf("--ttl soon: %d %q", r.code, r.stderr)
	}
	revoke := gocli(t, "token", "revoke", "--token", token, "--config", cfg)
	if revoke.code != 0 || revoke.json(t)["revoked"] == nil {
		t.Errorf("token revoke: %d %s", revoke.code, revoke.stdout)
	}
	if r := gocli(t, "authorize", "--token", child.json(t)["token"].(string), "--action", "read", "--resource", "crm.customer/c-1", "--config", cfg); r.code != 2 || r.json(t)["reason"] != "token_revoked" {
		t.Errorf("a child of a revoked token: %d %s", r.code, r.stdout)
	}
	carolToken := gocli(t, "token", "issue", "--user", "carol", "--agent", "support-bot", "--cap", "@"+capFile, "--raw", "--config", cfg).stdout
	if r := gocli(t, "token", "revoke", "--user", "carol", "--id", "ignored", "--config", cfg); r.code != 0 || r.json(t)["revoked_user"] != "carol" || r.json(t)["issued_up_to"] == nil {
		t.Errorf("token revoke --user: %d %s", r.code, r.stdout)
	}
	if r := gocli(t, "authorize", "--token", carolToken, "--action", "read", "--resource", "crm.customer/c-1", "--config", cfg); r.code != 2 || r.json(t)["reason"] != "token_revoked" {
		t.Errorf("a token of a revoked user: %d %s", r.code, r.stdout)
	}
	if r := gocli(t, "token", "revoke", "--id", "some-id", "--config", cfg); r.code != 0 || r.json(t)["revoked"] != "some-id" {
		t.Errorf("token revoke --id: %d %s", r.code, r.stdout)
	}

	// call: inline JSON, @file, standard input, and the default {}
	in := filepath.Join(dir, "in.json")
	if err := os.WriteFile(in, append([]byte("\xef\xbb\xbf"), MarshalJSON(map[string]any{"token": token})...), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, r := range []cliResult{
		gocli(t, "call", "inspect_token", "--input", string(MarshalJSON(map[string]any{"token": token})), "--config", cfg),
		gocli(t, "call", "inspect_token", "--input", "@"+in, "--config", cfg),
		runCmd(t, cleanEnv(), "", MarshalJSON(map[string]any{"token": token}), goCLI(t), "call", "inspect_token", "--input", "-", "--config", cfg),
	} {
		if r.code != 0 || r.json(t)["reason"] != "token_revoked" {
			t.Errorf("call inspect_token: %d %s %s", r.code, r.stdout, r.stderr)
		}
	}
	if r := gocli(t, "call", "approvals", "--config", cfg); r.code != 0 || r.json(t)["pending"] == nil {
		t.Errorf("call approvals: %d %s", r.code, r.stdout)
	}
	if r := gocli(t, "call", "nonsense", "--config", cfg); r.code != 1 || errCode(r.json(t)) != "unknown_op" {
		t.Errorf("call nonsense: %d %s", r.code, r.stdout)
	}

	// approvals and approve
	bob := gocli(t, "token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "@"+capFile, "--raw", "--config", cfg).stdout
	held := gocli(t, "authorize", "--token", bob, "--action", "create", "--resource", "billing.refund/r-1", "--context", `{"spend":{"currency":"EUR","amount":15000}}`, "--config", cfg)
	approval, _ := held.json(t)["approval"].(map[string]any)
	if held.code != 2 || approval["id"] == nil {
		t.Fatalf("a held request: %d %s", held.code, held.stdout)
	}
	if r := gocli(t, "approvals", "--config", cfg); r.code != 0 || len(r.json(t)["pending"].(map[string]any)) != 1 {
		t.Errorf("approvals: %d %s", r.code, r.stdout)
	}
	if r := gocli(t, "approve", approval["id"].(string), "--by", "alice", "--config", cfg); r.code != 1 || errCode(r.json(t)) != "self_approval" {
		t.Errorf("self approval: %d %s", r.code, r.stdout)
	}
	if r := gocli(t, "approve", approval["id"].(string), "--by", "bob", "--config", cfg); r.code != 0 || r.json(t)["by"] != "bob" {
		t.Errorf("approve: %d %s", r.code, r.stdout)
	}

	// audit
	verify := gocli(t, "audit", "verify", "--config", cfg)
	if verify.code != 0 || verify.json(t)["records"].(int64) < 10 {
		t.Errorf("audit verify: %d %s", verify.code, verify.stdout)
	}
	tail := gocli(t, "audit", "tail", "-n", "2", "--config", cfg)
	if lines := strings.Split(tail.stdout, "\n"); tail.code != 0 || len(lines) != 2 || !strings.Contains(lines[1], `"event":"approval_granted"`) {
		t.Errorf("audit tail -n 2: %d %q", tail.code, tail.stdout)
	}
	log := filepath.Join(dir, "state", "audit.jsonl")
	raw, _ := os.ReadFile(log)
	if err := os.WriteFile(log, []byte(strings.Replace(string(raw), `"user":"alice"`, `"user":"mallory"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := gocli(t, "audit", "verify", "--config", cfg); r.code != 1 || !strings.Contains(r.stderr, "audit_broken") {
		t.Errorf("audit verify on a tampered log: %d %q %q", r.code, r.stdout, r.stderr)
	}

	// help, version, unknown command
	if r := gocli(t, "--help"); r.code != 0 || !strings.Contains(r.stdout, "USAGE") {
		t.Errorf("--help: %d", r.code)
	}
	if r := gocli(t, "version"); r.code != 0 || r.stdout != "smartdelegate 0.3.0 (go)" {
		t.Errorf("version: %d %q", r.code, r.stdout)
	}
	if r := gocli(t, "frobnicate"); r.code != 1 || !strings.Contains(r.stderr, "USAGE") {
		t.Errorf("unknown command: %d", r.code)
	}
}

func TestCLIBundleKeygenAndSign(t *testing.T) {
	dir, cfg, _ := cliSetup(t, nil)
	prefix := filepath.Join(dir, "release")
	if r := gocli(t, "bundle", "keygen", prefix); r.code != 0 || !strings.Contains(r.stdout, "bundle_public_key") {
		t.Fatalf("bundle keygen: %d %s %s", r.code, r.stdout, r.stderr)
	}
	if st, err := os.Stat(prefix + ".key"); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("the private key must be readable by its owner only: %v %v", st.Mode(), err)
	}
	public, _ := os.ReadFile(prefix + ".pub")
	sign := gocli(t, "bundle", "sign", "--key", prefix+".key", "--config", cfg)
	if sign.code != 0 || !regexp.MustCompile(`^signed bundle version [0-9a-f]{64} with key [0-9a-f]{16}$`).MatchString(sign.stdout) {
		t.Fatalf("bundle sign: %d %q %q", sign.code, sign.stdout, sign.stderr)
	}
	_, signedCfg, _ := cliSetup(t, map[string]any{"bundle_dir": filepath.Join(dir, "conf", "bundle"), "bundle_public_key": string(public)})
	info := gocli(t, "info", "--config", signedCfg)
	if info.code != 0 || !strings.HasSuffix(sign.stdout, info.json(t)["bundle_signed_by"].(string)) {
		t.Errorf("a signed bundle: %d %s %s", info.code, info.stdout, info.stderr)
	}
	if r := gocli(t, "policy", "check", "--config", signedCfg); r.code != 0 || !strings.HasPrefix(r.stdout, "bundle loads: ") {
		t.Errorf("policy check: %d %q", r.code, r.stdout)
	}
	if r := gocli(t, "policy", "test", "--config", signedCfg); r.code != 0 || !strings.Contains(r.stdout, ", 0 failed") {
		t.Errorf("policy test: %d %q %q", r.code, r.stdout, r.stderr)
	}
	catalog := filepath.Join(dir, "conf", "bundle", "catalog.json")
	raw, _ := os.ReadFile(catalog)
	if err := os.WriteFile(catalog, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := gocli(t, "info", "--config", signedCfg); r.code != 1 || !strings.Contains(r.stderr, "bundle_signature") {
		t.Errorf("a bundle changed after signing: %d %q", r.code, r.stderr)
	}
}

func TestCLIConformance(t *testing.T) {
	root := repoRoot(t)
	want := []string{"go policy evaluation (against real Cedar's answers): 95 cases, 0 failed", "go conformance: 78 cases, 0 failed"}
	check := func(name string, r cliResult, lines []string) {
		t.Helper()
		if r.code != 0 || r.stdout != strings.Join(lines, "\n") {
			t.Errorf("%s: exit %d\n%s\n%s", name, r.code, r.stdout, r.stderr)
		}
	}
	// no arguments: the repository is found from the working directory upwards
	check("from ports/go", runCmd(t, cleanEnv(), filepath.Join(root, "ports", "go"), nil, goCLI(t), "conformance"), want)
	check("--root", runCmd(t, cleanEnv(), t.TempDir(), nil, goCLI(t), "conformance", "--root", root), want)
	check("explicit directories", runCmd(t, cleanEnv(), root, nil, goCLI(t), "conformance", filepath.Join("spec", "conformance", "vectors"),
		filepath.Join("spec", "conformance", "bundle")), want)
	// outside the repository, with directories: the vectors alone
	outside := runCmd(t, cleanEnv(), t.TempDir(), nil, goCLI(t), "conformance", filepath.Join(root, "spec", "conformance", "vectors"), specBundle(t))
	check("outside the repository", outside, want[1:])
	if r := runCmd(t, cleanEnv(), t.TempDir(), nil, goCLI(t), "conformance"); r.code != 1 {
		t.Errorf("outside the repository without directories: exit %d", r.code)
	}
	// a failing vector is reported and makes the exit code 1
	dir := t.TempDir()
	writeJSONFile(t, filepath.Join(dir, "x.json"), mustParse(t, `{"suite":"x","cases":[{"name":"wrong on purpose","steps":[{"op":"info","input":{},"expect":{"mode":"shadow"}}]},
		{"name":"right","steps":[{"op":"info","input":{},"expect":{"mode":"enforce"}}]}]}`))
	failing := runCmd(t, cleanEnv(), t.TempDir(), nil, goCLI(t), "conformance", dir, specBundle(t))
	if failing.code != 1 || !strings.Contains(failing.stdout, `FAIL "wrong on purpose"`) || !strings.HasSuffix(failing.stdout, "go conformance: 2 cases, 1 failed") {
		t.Errorf("a failing vector: exit %d\n%s", failing.code, failing.stdout)
	}
	// run_conformance.sh
	if _, err := exec.LookPath("bash"); err != nil {
		t.Log("bash not found: run_conformance.sh not run")
		return
	}
	script := runCmd(t, cleanEnv(), t.TempDir(), nil, filepath.Join(root, "ports", "go", "run_conformance.sh"))
	check("run_conformance.sh", script, want)
}

func TestCLIServe(t *testing.T) {
	_, cfg, _ := cliSetup(t, map[string]any{"admin_key": testAdmin, "pep_key": testPep})
	cmd := exec.Command(goCLI(t), "serve", "--config", cfg, "--listen", "127.0.0.1:0")
	cmd.Env = cleanEnv()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	stopped := false
	defer func() {
		if !stopped {
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	lineCh := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stderr).ReadString('\n')
		lineCh <- line
		done <- cmd.Wait()
	}()
	var line string
	select {
	case line = <-lineCh:
	case <-time.After(20 * time.Second):
		t.Fatal("the daemon printed no startup line")
	}
	m := regexp.MustCompile(`^smartdelegate daemon listening on (http://127\.0\.0\.1:\d+)\n$`).FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("startup line: %q", line)
	}
	if code, body, _ := do(t, "GET", m[1]+"/healthz", "", nil); code != 200 || body["ok"] != true {
		t.Errorf("healthz: %d %v", code, body)
	}
	client := NewClient(m[1], testPep, testAdmin)
	token := issue(t, client, nil)["token"]
	if r := client.Call("authorize", readRequest(token)); r["effect"] != "allow" {
		t.Errorf("authorize through the daemon: %s", Canon(r))
	}
	if code, _, _ := do(t, "GET", m[1]+"/v1/info", "", nil); code != http.StatusUnauthorized {
		t.Errorf("info without a key: %d", code)
	}
	// an interrupt stops it cleanly
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Errorf("exit after an interrupt: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Error("the daemon did not stop on an interrupt")
	}

	// without keys of 16 characters or more it refuses to start
	_, noKeys, _ := cliSetup(t, map[string]any{"admin_key": "short"})
	if r := gocli(t, "serve", "--config", noKeys, "--listen", "127.0.0.1:0"); r.code != 1 || !strings.Contains(r.stderr, "serve needs admin_key and pep_key") {
		t.Errorf("serve without keys: %d %q", r.code, r.stderr)
	}
	// the keys can come from the environment
	env := runCmd(t, cleanEnv("SMARTDELEGATE_ADMIN_KEY=short", "SMARTDELEGATE_PEP_KEY="+testPep), "", nil, goCLI(t), "serve", "--config", cfg, "--listen", "127.0.0.1:0")
	if env.code != 1 || !strings.Contains(env.stderr, "serve needs admin_key and pep_key") {
		t.Errorf("keys from the environment override the file: %d %q", env.code, env.stderr)
	}
}
