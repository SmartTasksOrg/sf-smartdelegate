// Command smartdelegate-go is the command line of the Go port of SmartDelegate.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	sd "github.com/SmartTasksOrg/sf-smartdelegate/ports/go"
)

const help = `smartdelegate-go - identity and access management for LLM agents (Go port)

USAGE
  smartdelegate-go <command> [options]       JSON options accept @file, e.g. --cap @cap.json

SETUP
  info                                  version, policy version, mode, key id
  policy check                          load the bundle and report problems
  policy test                           run the bundle's tests/*.json
  bundle keygen <prefix>                write <prefix>.key and <prefix>.pub (Ed25519)
  bundle sign --key <file>              sign the bundle (writes bundle.sig.json)

TOKENS
  token issue --user U --agent A (--cap JSON | --role R [--cap JSON]) [--groups g1,g2]
              [--ttl S] [--tenant T] [--task X] [--id-token JWT] [--raw]
  token exchange --token T --actor A [--cap JSON] [--ttl S] [--raw]
  token inspect --token T
  token revoke --id TOKEN_ID | --token T | --user U     --user ends every token already
                                        issued for that human (offboarding)

DECISIONS
  authorize --token T --action A --resource path/id [--attrs JSON] [--context JSON]
            [--data JSON] [--strict] [--dry-run]      exit code 0 allow, 2 deny, 1 error
  explain   (same options)              show every check and every field decision
  approvals                             list held requests
  approve <approval_id> --by USER

AUDIT
  audit verify                          recompute the hash chain
  audit tail [-n N]

SERVERS
  serve [--listen 127.0.0.1:8181]       REST decision daemon

OTHER
  call <op> [--input JSON|@file|-]      any operation of spec/API.md, JSON in, JSON out
  conformance [<vectors dir> <bundle dir>] [--root DIR]
                                        policy evaluation cases and conformance vectors.
                                        Without directories: the repository's spec/, found
                                        from --root or from the working directory upwards
  version

CONFIG
  --config FILE (or SMARTDELEGATE_CONFIG, or ./smartdelegate.json); --bundle DIR and --state DIR override it.
  --shadow logs would-be denials without enforcing them.
`

var switches = map[string]bool{"raw": true, "strict": true, "dry-run": true, "shadow": true, "help": true}

type exit int

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "smartdelegate: %s\n", fmt.Sprintf(format, a...))
	panic(exit(1))
}

type args struct {
	pos   []string
	flags map[string]string
	rest  []string
}

func parseArgs(argv []string) *args {
	a := &args{flags: map[string]string{}}
	for i := 0; i < len(argv); i++ {
		x := argv[i]
		if x == "--" {
			a.rest = argv[i+1:]
			break
		}
		name, isFlag := "", false
		if strings.HasPrefix(x, "--") {
			name, isFlag = x[2:], true
		} else if strings.HasPrefix(x, "-") && len(x) == 2 {
			name, isFlag = x[1:], true
		}
		switch {
		case !isFlag:
			a.pos = append(a.pos, x)
		case switches[name]:
			a.flags[name] = "true"
		case strings.Contains(name, "="):
			k, v, _ := strings.Cut(name, "=")
			a.flags[k] = v
		default:
			i++
			if i >= len(argv) {
				die("--%s needs a value", name)
			}
			a.flags[name] = argv[i]
		}
	}
	if a.has("help") {
		a.pos = []string{"help"}
	}
	return a
}

func (a *args) flag(k string) string { return a.flags[k] }

func (a *args) has(k string) bool {
	_, ok := a.flags[k]
	return ok
}

func (a *args) req(k string) string {
	if !a.has(k) {
		die("--%s is required", k)
	}
	return a.flags[k]
}

func (a *args) at(n int, usage string) string {
	if len(a.pos) <= n {
		die("%s", usage)
	}
	return a.pos[n]
}

func stripBOM(raw []byte) []byte {
	return bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
}

// jsonArg reads a JSON value given inline or as @file.
func jsonArg(s string) any {
	text := []byte(s)
	if strings.HasPrefix(s, "@") {
		raw, err := os.ReadFile(s[1:])
		if err != nil {
			die("%s: %v", s[1:], err)
		}
		text = stripBOM(raw)
	}
	v, err := sd.ParseJSON(text)
	if err != nil {
		die("not valid JSON (%v): %s", err, s)
	}
	return v
}

// loadConfig is the config file plus command-line overrides. Relative paths
// in the file are relative to the file.
func loadConfig(a *args) map[string]any {
	path := a.flag("config")
	if path == "" {
		path = os.Getenv("SMARTDELEGATE_CONFIG")
	}
	if path == "" {
		if _, err := os.Stat("smartdelegate.json"); err == nil {
			path = "smartdelegate.json"
		}
	}
	cfg := map[string]any{}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			die("%s: %v", path, err)
		}
		v, err := sd.ParseJSON(stripBOM(raw))
		if err != nil {
			die("%s: %v", path, err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			die("%s: the configuration must be a JSON object", path)
		}
		cfg = m
		abs, err := filepath.Abs(path)
		if err != nil {
			die("%s: %v", path, err)
		}
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			abs = real
		}
		base := filepath.Dir(abs)
		fix := func(m map[string]any, k string) {
			if p, ok := m[k].(string); ok && !filepath.IsAbs(p) {
				m[k] = filepath.Join(base, p)
			}
		}
		fix(cfg, "bundle_dir")
		fix(cfg, "state_dir")
		if idp, ok := cfg["idp"].(map[string]any); ok {
			fix(idp, "jwks_file")
		}
	}
	if a.flag("bundle") != "" {
		cfg["bundle_dir"] = a.flag("bundle")
	}
	if a.flag("state") != "" {
		cfg["state_dir"] = a.flag("state")
	}
	if a.has("shadow") {
		cfg["mode"] = "shadow"
	}
	for k, env := range map[string]string{"admin_key": "SMARTDELEGATE_ADMIN_KEY", "pep_key": "SMARTDELEGATE_PEP_KEY"} {
		if v := os.Getenv(env); v != "" {
			cfg[k] = v
		}
	}
	if s, _ := cfg["bundle_dir"].(string); s == "" {
		die("no bundle: pass --config FILE or --bundle DIR")
	}
	return cfg
}

func engineFrom(a *args) (*sd.Engine, map[string]any) {
	cfg := loadConfig(a)
	e, err := sd.NewEngine(cfg)
	if err != nil {
		die("%v", err)
	}
	return e, cfg
}

func finish(v map[string]any) int {
	fmt.Println(sd.MarshalIndent(v))
	if v["ok"] != true {
		return 1
	}
	if v["effect"] == "deny" {
		return 2
	}
	return 0
}

func call(a *args, op string, input any) map[string]any {
	e, _ := engineFrom(a)
	defer e.Close()
	return e.Call(op, input)
}

func decisionInput(a *args) (map[string]any, string) {
	res := a.req("resource")
	path, rid, _ := strings.Cut(res, "/")
	if rid == "" {
		rid = "any"
	}
	resource := map[string]any{"path": path, "id": rid}
	i := map[string]any{"action": a.req("action"), "resource": resource}
	if a.flag("token") != "" {
		i["token"] = a.flag("token")
	}
	if a.flag("attrs") != "" {
		resource["attrs"] = jsonArg(a.flag("attrs"))
	}
	if a.flag("context") != "" {
		i["context"] = jsonArg(a.flag("context"))
	}
	if a.has("strict") {
		i["strict"] = true
	}
	if a.has("dry-run") {
		i["dry_run"] = true
	}
	if a.flag("data") != "" {
		i["data"] = jsonArg(a.flag("data"))
		return i, "filter"
	}
	return i, "authorize"
}

func ttlOf(a *args, i map[string]any) {
	if a.flag("ttl") != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(a.flag("ttl")), 10, 64)
		if err != nil {
			die("--ttl must be a number of seconds")
		}
		i["ttl"] = n
	}
}

func tokenOut(v map[string]any, a *args) int {
	if a.has("raw") && v["ok"] == true {
		fmt.Println(v["token"])
		return 0
	}
	return finish(v)
}

func report(r sd.Report, label string) int {
	for _, c := range r.Results {
		if !c.Passed {
			fmt.Printf("FAIL %s\n", strconv.Quote(c.Name))
			for _, f := range c.Failures {
				fmt.Printf("  %s\n", f)
			}
		}
	}
	fmt.Printf("%s: %d cases, %d failed\n", label, r.Total, r.Failed)
	if r.Failed != 0 {
		return 1
	}
	return 0
}

// findRoot looks for the repository root (the directory holding
// spec/conformance) from dir upwards.
func findRoot(dir string) string {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		if st, err := os.Stat(filepath.Join(dir, "spec", "conformance", "vectors")); err == nil && st.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func conformance(a *args) int {
	root := a.flag("root")
	if root == "" {
		root = findRoot(".")
	}
	var vectors, bundle string
	switch {
	case len(a.pos) >= 3:
		vectors, bundle = a.pos[1], a.pos[2]
	case len(a.pos) == 2:
		vectors, bundle = a.pos[1], filepath.Join("spec", "conformance", "bundle")
	default:
		if root == "" {
			die("conformance: spec/conformance not found from the working directory upwards; pass --root DIR, or <vectors dir> <bundle dir>")
		}
		vectors, bundle = filepath.Join(root, "spec", "conformance", "vectors"), filepath.Join(root, "spec", "conformance", "bundle")
	}
	code := 0
	if root != "" {
		r, err := sd.RunEvalCases(filepath.Join(root, "spec", "conformance", "eval", "cases.json"))
		if err != nil {
			die("%v", err)
		}
		code |= report(r, "go policy evaluation (against real Cedar's answers)")
	} else {
		fmt.Fprintln(os.Stderr, "smartdelegate: spec/conformance/eval/cases.json not found (pass --root DIR); running the vectors only")
	}
	r, err := sd.RunVectors(vectors, bundle)
	if err != nil {
		die("%v", err)
	}
	code |= report(r, "go conformance")
	return code
}

func serve(a *args) int {
	e, cfg := engineFrom(a)
	defer e.Close()
	listen := a.flag("listen")
	if listen == "" {
		listen, _ = cfg["listen"].(string)
	}
	if listen == "" {
		listen = "127.0.0.1:8181"
	}
	admin, _ := cfg["admin_key"].(string)
	pep, _ := cfg["pep_key"].(string)
	srv, err := sd.Listen(e, listen, admin, pep)
	if err != nil {
		die("%v", err)
	}
	fmt.Fprintf(os.Stderr, "smartdelegate daemon listening on %s\n", srv.URL)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	select {
	case <-stop:
		_ = srv.Close()
	case err := <-done:
		if err != nil {
			die("%v", err)
		}
	}
	return 0
}

func run(argv []string) int {
	a := parseArgs(argv)
	cmd, sub := "help", ""
	if len(a.pos) > 0 {
		cmd = a.pos[0]
	}
	if len(a.pos) > 1 {
		sub = a.pos[1]
	}
	both := cmd + " " + sub
	switch {
	case cmd == "help":
		fmt.Print(help)
		return 0
	case cmd == "version":
		fmt.Printf("smartdelegate %s (%s)\n", sd.Version, sd.Implementation)
		return 0
	case cmd == "info":
		return finish(call(a, "info", map[string]any{}))
	case both == "policy check":
		info := call(a, "info", map[string]any{})
		fmt.Printf("bundle loads: %v policies, version %v\n", info["policies"], info["policy_version"])
		return 0
	case both == "policy test":
		bundleDir, _ := loadConfig(a)["bundle_dir"].(string)
		r, err := sd.RunBundleTests(bundleDir)
		if err != nil {
			die("%v", err)
		}
		for _, c := range r.Results {
			if c.Passed {
				fmt.Println("ok  ", c.Name)
			} else {
				fmt.Println("FAIL", c.Name)
				for _, f := range c.Failures {
					fmt.Printf("  %s\n", f)
				}
			}
		}
		fmt.Printf("%d tests, %d failed\n", r.Total, r.Failed)
		if r.Failed != 0 {
			return 1
		}
		return 0
	case both == "bundle keygen":
		prefix := a.at(2, "usage: smartdelegate-go bundle keygen <prefix>")
		sk, pk, err := sd.Keygen()
		if err != nil {
			die("%v", err)
		}
		_ = os.Remove(prefix + ".key") // so the mode below applies to a file that already existed
		if err := os.WriteFile(prefix+".key", []byte(sk), 0o600); err != nil {
			die("%v", err)
		}
		if err := os.WriteFile(prefix+".pub", []byte(pk), 0o644); err != nil {
			die("%v", err)
		}
		fmt.Printf("wrote %s.key (keep secret) and %s.pub\nset \"bundle_public_key\": \"%s\" in smartdelegate.json to require signed bundles\n", prefix, prefix, pk)
		return 0
	case both == "bundle sign":
		bundleDir, _ := loadConfig(a)["bundle_dir"].(string)
		key, err := os.ReadFile(a.req("key"))
		if err != nil {
			die("%v", err)
		}
		v, err := sd.SignBundle(bundleDir, string(key))
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("signed bundle version %v with key %v\n", v["version"], v["key_id"])
		return 0
	case both == "bundle compile":
		die("compiling .cedar to policies.json needs the Cedar toolchain: run `smartdelegate bundle compile` from the Rust port (ports/rust)")
	case both == "token issue":
		i := map[string]any{"agent": a.req("agent")}
		if a.flag("cap") != "" {
			i["cap"] = jsonArg(a.flag("cap"))
		} else if a.flag("role") == "" {
			die("--cap JSON or --role NAME is required")
		}
		for k, f := range map[string]string{"user": "user", "tenant": "tenant", "task": "task", "id_token": "id-token", "role": "role"} {
			if a.flag(f) != "" {
				i[k] = a.flag(f)
			}
		}
		if a.has("groups") {
			groups := []any{}
			for _, g := range strings.Split(a.flag("groups"), ",") {
				if g != "" {
					groups = append(groups, g)
				}
			}
			i["groups"] = groups
		}
		ttlOf(a, i)
		return tokenOut(call(a, "issue_token", i), a)
	case both == "token exchange":
		i := map[string]any{"subject_token": a.req("token"), "actor": a.req("actor")}
		if a.flag("cap") != "" {
			i["cap"] = jsonArg(a.flag("cap"))
		}
		ttlOf(a, i)
		return tokenOut(call(a, "exchange_token", i), a)
	case both == "token inspect":
		return finish(call(a, "inspect_token", map[string]any{"token": a.req("token")}))
	case both == "token revoke":
		i := map[string]any{"by": "cli"}
		if a.flag("user") != "" {
			i["user"] = a.flag("user")
		} else if a.flag("id") != "" {
			i["token_id"] = a.flag("id")
		} else {
			i["token"] = a.req("token")
		}
		return finish(call(a, "revoke", i))
	case cmd == "call" && sub != "":
		// any operation, input as JSON: the form other ports and scripts use
		raw := a.flag("input")
		if raw == "" {
			raw = "{}"
		}
		var input any
		if raw == "-" {
			text, err := io.ReadAll(os.Stdin)
			if err != nil {
				die("%v", err)
			}
			v, err := sd.ParseJSON(text)
			if err != nil {
				die("not valid JSON (%v): standard input", err)
			}
			input = v
		} else {
			input = jsonArg(raw)
		}
		return finish(call(a, sub, input))
	case cmd == "authorize":
		i, op := decisionInput(a)
		return finish(call(a, op, i))
	case cmd == "explain":
		i, _ := decisionInput(a)
		return finish(call(a, "explain", i))
	case cmd == "approvals":
		return finish(call(a, "approvals", map[string]any{}))
	case cmd == "approve" && sub != "":
		return finish(call(a, "approve", map[string]any{"approval_id": sub, "by": a.req("by")}))
	case both == "audit verify":
		return finish(call(a, "audit_verify", map[string]any{}))
	case both == "audit tail":
		n := int64(20)
		if a.flag("n") != "" {
			v, err := strconv.ParseInt(strings.TrimSpace(a.flag("n")), 10, 64)
			if err != nil {
				die("-n must be a number")
			}
			n = v
		}
		r := call(a, "audit_tail", map[string]any{"n": n})
		records, _ := r["records"].([]any)
		for _, rec := range records {
			fmt.Println(sd.Canon(rec))
		}
		return 0
	case cmd == "serve":
		return serve(a)
	case cmd == "conformance":
		return conformance(a)
	}
	fmt.Fprint(os.Stderr, help)
	return 1
}

func main() {
	code := 0
	func() {
		defer func() {
			if r := recover(); r != nil {
				c, ok := r.(exit)
				if !ok {
					panic(r)
				}
				code = int(c)
			}
		}()
		code = run(os.Args[1:])
	}()
	os.Exit(code)
}
