package smartdelegate

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const testNow = int64(1700000000)

// repoRoot is the repository root, found relative to this test file.
func repoRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "spec", "conformance", "vectors")); err != nil {
		t.Fatalf("repository root not found at %s: %v", root, err)
	}
	return root
}

func specBundle(t testing.TB) string {
	return filepath.Join(repoRoot(t), "spec", "conformance", "bundle")
}

func fullCap() map[string]any {
	return map[string]any{"actions": []any{"read", "create", "update"}, "resources": []any{"crm.customer/*", "billing.refund/*"},
		"budget": map[string]any{"EUR": int64(20000)}}
}

// newTestEngine is an engine on the conformance bundle with its own state
// directory (removed when the test ends).
func newTestEngine(t testing.TB, extra map[string]any) (*Engine, string) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	e, err := NewEngine(ConformanceConfig(specBundle(t), state, extra))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(e.Close)
	return e, state
}

func mustOK(t testing.TB, r map[string]any) map[string]any {
	t.Helper()
	if r["ok"] != true {
		t.Fatalf("expected ok, got %s", Canon(r))
	}
	return r
}

func errCode(r map[string]any) string {
	e, _ := r["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

func issue(t testing.TB, c Caller, extra map[string]any) map[string]any {
	t.Helper()
	in := map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap(), "now": testNow}
	for k, v := range extra {
		in[k] = v
	}
	return mustOK(t, c.Call("issue_token", in))
}

func readRequest(token any) map[string]any {
	return map[string]any{"token": token, "action": "read", "resource": map[string]any{"path": "crm.customer", "id": "c-1"}, "now": testNow}
}

func spendRequest(token any, amount int64, now int64) map[string]any {
	return map[string]any{"token": token, "action": "create", "resource": map[string]any{"path": "billing.refund", "id": "r-1"},
		"context": map[string]any{"spend": map[string]any{"currency": "EUR", "amount": amount}}, "now": now}
}

func writeJSONFile(t testing.TB, path string, v any) {
	t.Helper()
	if err := os.WriteFile(path, MarshalJSON(v), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---- the Python reference -----------------------------------------------------

var (
	pyOnce   sync.Once
	pyReason string
)

func cleanEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SMARTDELEGATE_") && !strings.HasPrefix(kv, "PYTHONPATH=") {
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

func pythonEnv(t testing.TB) []string {
	return cleanEnv("PYTHONPATH="+filepath.Join(repoRoot(t), "src"), "PYTHONDONTWRITEBYTECODE=1", "PYTHONIOENCODING=utf-8", "PYTHONUTF8=1")
}

// havePython reports whether the Python reference can run here.
func havePython(t testing.TB) bool {
	t.Helper()
	pyOnce.Do(func() {
		if _, err := exec.LookPath("python3"); err != nil {
			pyReason = "python3 is not installed"
			return
		}
		cmd := exec.Command("python3", "-c", "import cryptography, smartdelegate")
		cmd.Env = pythonEnv(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			pyReason = "the Python reference cannot be imported (is the `cryptography` package installed?): " + strings.TrimSpace(string(out))
		}
	})
	return pyReason == ""
}

// needPython skips the test when the Python reference cannot run here.
func needPython(t testing.TB) {
	t.Helper()
	if !havePython(t) {
		t.Skip("interoperability with the Python reference not tested: " + pyReason)
	}
}

type cliResult struct {
	code   int
	stdout string
	stderr string
}

func (r cliResult) json(t testing.TB) map[string]any {
	t.Helper()
	v, err := ParseJSON([]byte(r.stdout))
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		t.Fatalf("not a JSON object (exit %d): %q %q", r.code, r.stdout, r.stderr)
	}
	return m
}

func runCmd(t testing.TB, env []string, dir string, stdin []byte, name string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env, cmd.Dir = env, dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err := cmd.Run()
	res := cliResult{stdout: strings.TrimSpace(out.String()), stderr: errb.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		res.code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("%s %v: %v", name, args, err)
	}
	return res
}

// python runs the reference CLI: python3 -m sf_smartdelegate <args>.
func python(t testing.TB, args ...string) cliResult {
	t.Helper()
	return runCmd(t, pythonEnv(t), "", nil, "python3", append([]string{"-m", "sf_smartdelegate"}, args...)...)
}

// pythonCall runs one operation in the reference: call <op> --input - --config cfg.
func pythonCall(t testing.TB, cfg, op string, input any) map[string]any {
	t.Helper()
	r := runCmd(t, pythonEnv(t), "", MarshalJSON(input), "python3", "-m", "sf_smartdelegate", "call", op, "--input", "-", "--config", cfg)
	return r.json(t)
}

// ---- this port's CLI ------------------------------------------------------------

var (
	cliOnce sync.Once
	cliPath string
	cliErr  string
	cliDir  string
)

// goCLI builds cmd/smartdelegate-go once into a temporary directory.
func goCLI(t testing.TB) string {
	t.Helper()
	cliOnce.Do(func() {
		dir, err := os.MkdirTemp("", "smartdelegate-go-bin-")
		if err != nil {
			cliErr = err.Error()
			return
		}
		cliDir = dir
		name := "smartdelegate-go"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", filepath.Join(dir, name), "./cmd/smartdelegate-go")
		cmd.Dir = filepath.Join(repoRoot(t), "ports", "go")
		if out, err := cmd.CombinedOutput(); err != nil {
			cliErr = "go build: " + err.Error() + "\n" + string(out)
			return
		}
		cliPath = filepath.Join(dir, name)
	})
	if cliErr != "" {
		t.Fatal(cliErr)
	}
	return cliPath
}

func gocli(t testing.TB, args ...string) cliResult {
	t.Helper()
	return runCmd(t, cleanEnv(), "", nil, goCLI(t), args...)
}

func TestMain(m *testing.M) {
	code := m.Run()
	if cliDir != "" {
		_ = os.RemoveAll(cliDir)
	}
	os.Exit(code)
}
