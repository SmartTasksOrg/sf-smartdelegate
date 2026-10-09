package smartdelegate

// Runner for the shared conformance vectors, for a bundle's own tests and for
// the policy evaluation cases.
//
// A case is a list of steps; each step names an operation, its input and a
// partial expected result. `save` stores a value from a result and "$name" in
// a later input is replaced by it.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Caller is anything that runs an operation: an *Engine or a *Client.
type Caller interface {
	Call(op string, payload any) map[string]any
}

func substitute(v any, variables map[string]any) any {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, "$") {
			if val, ok := variables[x[1:]]; ok {
				return val
			}
		}
		return x
	case []any:
		out := make([]any, len(x))
		for i, el := range x {
			out[i] = substitute(el, variables)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, el := range x {
			out[k] = substitute(el, variables)
		}
		return out
	}
	return v
}

// Subset checks that every key in expect is present and equal in actual:
// objects recursively, everything else exactly. An expected null also
// matches a missing key. It returns the first mismatch, or "".
func Subset(expect, actual any, path string) string {
	em, eIsMap := expect.(map[string]any)
	am, aIsMap := actual.(map[string]any)
	if eIsMap && aIsMap {
		for _, k := range sortedKeys(em) {
			p := k
			if path != "" {
				p = path + "." + k
			}
			av, has := am[k]
			if !has {
				if em[k] == nil {
					continue
				}
				return fmt.Sprintf("%s: missing, expected %s", p, Canon(em[k]))
			}
			if m := Subset(em[k], av, p); m != "" {
				return m
			}
		}
		return ""
	}
	_, eBool := expect.(bool)
	_, aBool := actual.(bool)
	if eBool != aBool || !pyEqual(expect, actual) {
		return fmt.Sprintf("%s: expected %s, got %s", path, Canon(expect), Canon(actual))
	}
	return ""
}

// CaseResult is the outcome of one conformance case.
type CaseResult struct {
	Name     string
	Passed   bool
	Failures []string
}

// RunCase runs the steps of one case against a Caller.
func RunCase(c Caller, tc map[string]any) CaseResult {
	name, _ := tc["name"].(string)
	res := CaseResult{Name: name}
	variables := map[string]any{}
	steps, _ := tc["steps"].([]any)
	for n, s := range steps {
		step, _ := s.(map[string]any)
		op, _ := step["op"].(string)
		result := c.Call(op, substitute(step["input"], variables))
		if save, ok := step["save"].(map[string]any); ok {
			for name, key := range save {
				var cur any = result
				for _, part := range strings.Split(fmt.Sprint(key), ".") {
					if m, ok := cur.(map[string]any); ok {
						cur = m[part]
					} else {
						cur = nil
					}
				}
				variables[name] = cur
			}
		}
		expect := step["expect"]
		if !truthy(expect) {
			expect = map[string]any{}
		}
		if m := Subset(expect, any(result), ""); m != "" {
			res.Failures = append(res.Failures, fmt.Sprintf("step %d (%s): %s", n, op, m))
		}
	}
	res.Passed = len(res.Failures) == 0
	return res
}

// Report is the outcome of a suite.
type Report struct {
	Total   int
	Failed  int
	Results []CaseResult
}

func (r *Report) add(c CaseResult) {
	r.Total++
	if !c.Passed {
		r.Failed++
	}
	r.Results = append(r.Results, c)
}

// VectorSuite is one vectors/*.json file.
type VectorSuite struct {
	File   string
	Suite  string
	Config map[string]any
	Cases  []map[string]any
}

// LoadVectors reads every *.json file of a vectors directory, in name order.
func LoadVectors(dir string) ([]VectorSuite, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []VectorSuite
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		parsed, err := parseJSONBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", f, err)
		}
		doc, ok := parsed.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: not a JSON object", f)
		}
		s := VectorSuite{File: filepath.Base(f)}
		s.Suite, _ = doc["suite"].(string)
		s.Config, _ = doc["config"].(map[string]any)
		cases, _ := doc["cases"].([]any)
		for _, c := range cases {
			if cm, ok := c.(map[string]any); ok {
				s.Cases = append(s.Cases, cm)
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// ConformanceConfig is the configuration every port uses for the shared
// vectors, merged with the suite's own `config` when it has one.
func ConformanceConfig(bundleDir, stateDir string, extra map[string]any) map[string]any {
	cfg := map[string]any{"bundle_dir": bundleDir, "state_dir": stateDir, "allow_test_clock": true, "max_depth": int64(3)}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

// RunVectors runs every case against a fresh engine with its own state directory.
func RunVectors(vectorsDir, bundleDir string) (Report, error) {
	var rep Report
	suites, err := LoadVectors(vectorsDir)
	if err != nil {
		return rep, err
	}
	for _, s := range suites {
		for _, tc := range s.Cases {
			res, err := runFresh(ConformanceConfig(bundleDir, "", s.Config), true, tc)
			if err != nil {
				return rep, err
			}
			rep.add(res)
		}
	}
	return rep, nil
}

func runFresh(cfg map[string]any, withState bool, tc map[string]any) (CaseResult, error) {
	if withState {
		dir, err := os.MkdirTemp("", "smartdelegate-conf-")
		if err != nil {
			return CaseResult{}, err
		}
		defer os.RemoveAll(dir)
		cfg["state_dir"] = dir
	}
	e, err := NewEngine(cfg)
	if err != nil {
		return CaseResult{}, err
	}
	defer e.Close()
	return RunCase(e, tc), nil
}

// RunBundleTests runs <bundle>/tests/*.json against a throwaway engine per
// case: no state directory, no audit log, test clock on, caller-supplied
// chains trusted.
func RunBundleTests(bundleDir string) (Report, error) {
	var rep Report
	suites, err := LoadVectors(filepath.Join(bundleDir, "tests"))
	if err != nil {
		return rep, err
	}
	for _, s := range suites {
		for _, tc := range s.Cases {
			cfg := map[string]any{"bundle_dir": bundleDir, "allow_test_clock": true, "trust_caller_chain": true, "audit": false}
			res, err := runFresh(cfg, false, tc)
			if err != nil {
				return rep, err
			}
			rep.add(res)
		}
	}
	return rep, nil
}

// RunEvalCases runs spec/conformance/eval/cases.json: the policy evaluator
// against answers recorded from the real Cedar engine.
func RunEvalCases(path string) (Report, error) {
	var rep Report
	raw, err := os.ReadFile(path)
	if err != nil {
		return rep, err
	}
	parsed, err := parseJSONBytes(raw)
	if err != nil {
		return rep, fmt.Errorf("%s: %v", path, err)
	}
	doc, _ := parsed.(map[string]any)
	entities, _ := doc["entities"].([]any)
	store, err := NewStore(entities)
	if err != nil {
		return rep, fmt.Errorf("%s: entities: %v", path, err)
	}
	cases, _ := doc["cases"].([]any)
	for _, c := range cases {
		tc, _ := c.(map[string]any)
		rep.add(runEvalCase(tc, store))
	}
	return rep, nil
}

func runEvalCase(tc map[string]any, store *Store) (res CaseResult) {
	res.Name, _ = tc["name"].(string)
	fail := func(format string, a ...any) CaseResult {
		res.Failures = append(res.Failures, fmt.Sprintf(format, a...))
		return res
	}
	defer func() {
		if r := recover(); r != nil {
			res.Passed = false
			res.Failures = append(res.Failures, fmt.Sprintf("panic: %v", r))
		}
	}()
	expect, _ := tc["expect"].(map[string]any)
	wantLoadError := expect["load_error"] == true
	policies := map[string]*Policy{}
	raw, _ := tc["policies"].(map[string]any)
	for _, id := range sortedKeys(raw) {
		p, err := NewPolicy(id, raw[id])
		if err != nil {
			if wantLoadError {
				res.Passed = true
				return res
			}
			return fail("refused at load: %v", err)
		}
		policies[id] = p
	}
	if wantLoadError {
		return fail("should have been refused at load")
	}
	request, _ := tc["request"].(map[string]any)
	pr, _ := request["principal"].([]any)
	rs, _ := request["resource"].([]any)
	action, _ := request["action"].(string)
	if len(pr) != 2 || len(rs) != 2 {
		return fail("malformed request")
	}
	ctx, err := fromJSON(request["context"])
	ctxRec, ok := ctx.(map[string]any)
	if err != nil || !ok {
		return fail("context is not a Cedar record: %v", err)
	}
	got := IsAuthorized(policies, &Env{Principal: Entity{pr[0].(string), pr[1].(string)}, Action: Entity{"Action", action},
		Resource: Entity{rs[0].(string), rs[1].(string)}, Context: ctxRec, Store: store})
	decision := "deny"
	if got.Allow {
		decision = "allow"
	}
	errIDs := []string{}
	for _, e := range got.Errors {
		errIDs = append(errIDs, e.ID)
	}
	sort.Strings(errIDs)
	actual := map[string]any{"decision": decision, "reasons": strList(got.Reasons), "errors": strList(errIDs)}
	if !pyEqual(actual, any(expect)) {
		return fail("got %s, Cedar says %s", Canon(actual), Canon(expect))
	}
	res.Passed = true
	return res
}
