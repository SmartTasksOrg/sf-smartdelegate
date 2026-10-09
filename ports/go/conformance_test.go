package smartdelegate

import (
	"path/filepath"
	"testing"
)

// (1) The policy evaluator against answers recorded from the real Cedar engine.
func TestEvalCases(t *testing.T) {
	rep, err := RunEvalCases(filepath.Join(repoRoot(t), "spec", "conformance", "eval", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if !r.Passed {
			t.Errorf("%s: %v", r.Name, r.Failures)
		}
	}
	if rep.Total != 95 {
		t.Errorf("expected the 95 eval cases, ran %d", rep.Total)
	}
	t.Logf("policy evaluation: %d cases, %d failed", rep.Total, rep.Failed)
}

func vectorSuites(t *testing.T) []VectorSuite {
	t.Helper()
	suites, err := LoadVectors(filepath.Join(repoRoot(t), "spec", "conformance", "vectors"))
	if err != nil {
		t.Fatal(err)
	}
	return suites
}

func countSteps(tc map[string]any) int {
	steps, _ := tc["steps"].([]any)
	return len(steps)
}

// (2) The conformance vectors in-process: a fresh engine and state directory per case.
func TestConformanceInProcess(t *testing.T) {
	cases, steps, failed := 0, 0, 0
	for _, s := range vectorSuites(t) {
		for _, tc := range s.Cases {
			e, _ := newTestEngine(t, s.Config)
			res := RunCase(e, tc)
			e.Close()
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
	t.Logf("conformance in-process: %d cases (%d steps), %d failed", cases, steps, failed)
}

// (3) The conformance vectors over REST: this port's daemon, this port's client.
func TestConformanceOverREST(t *testing.T) {
	const admin, pep = "admin-key-for-tests-0123456789", "pep-key-for-tests-0123456789"
	cases, steps, failed := 0, 0, 0
	for _, s := range vectorSuites(t) {
		for _, tc := range s.Cases {
			e, _ := newTestEngine(t, s.Config)
			srv, err := Listen(e, "127.0.0.1:0", admin, pep)
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = srv.Serve() }()
			res := RunCase(NewClient(srv.URL, pep, admin), tc)
			_ = srv.Close()
			e.Close()
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
	t.Logf("conformance over REST: %d cases (%d steps), %d failed", cases, steps, failed)
}

// The runner itself: RunVectors is what the CLI uses, and a wrong expectation must fail.
func TestRunnerReportsMismatches(t *testing.T) {
	rep, err := RunVectors(filepath.Join(repoRoot(t), "spec", "conformance", "vectors"), specBundle(t))
	if err != nil || rep.Total != 78 || rep.Failed != 0 {
		t.Fatalf("RunVectors: %d cases, %d failed, %v", rep.Total, rep.Failed, err)
	}
	e, _ := newTestEngine(t, nil)
	parse := func(s string) map[string]any { v, _ := ParseJSON([]byte(s)); return v.(map[string]any) }
	wrong := []string{
		`{"steps":[{"op":"info","input":{},"expect":{"ok":false}}]}`,
		`{"steps":[{"op":"info","input":{},"expect":{"mode":"shadow"}}]}`,
		`{"steps":[{"op":"info","input":{},"expect":{"missing":1}}]}`,
		`{"steps":[{"op":"info","input":{},"expect":{"can_issue":1}}]}`,
		`{"steps":[{"op":"nonsense","input":{},"expect":{"ok":true}}]}`,
		`{"steps":[{"op":"info","input":{},"save":{"m":"mode"}},{"op":"inspect_token","input":{"token":"$m"},"expect":{"valid":true}}]}`,
	}
	for _, w := range wrong {
		if RunCase(e, parse(w)).Passed {
			t.Errorf("a wrong expectation passed: %s", w)
		}
	}
	right := `{"steps":[{"op":"info","input":{},"expect":{"ok":true,"mode":"enforce","oidc":null,"nothing":null,"version":"0.3.0","implementation":"go"},"save":{"m":"mode"}},
		{"op":"inspect_token","input":{"token":"$m"},"expect":{"valid":false,"reason":"token_invalid"}}]}`
	if res := RunCase(e, parse(right)); !res.Passed {
		t.Errorf("a right expectation failed: %v", res.Failures)
	}
	bt, err := RunBundleTests(specBundle(t))
	if err != nil || bt.Failed != 0 {
		t.Errorf("the conformance bundle's own tests: %d cases, %d failed, %v", bt.Total, bt.Failed, err)
	}
}
