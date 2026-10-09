package smartdelegate

// (4) Interoperability with the Python reference (src/sf_smartdelegate), run as
// `python3 -m sf_smartdelegate ...`. Every test here is skipped, with the
// reason, when python3 or its `cryptography` package is missing.

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func pyConfig(t *testing.T, name string, cfg map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	writeJSONFile(t, path, cfg)
	return path
}

func readTrim(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

// sameDecision compares what two engines say about one request, leaving out
// what legitimately differs (ids, wording).
func sameDecision(t *testing.T, what string, a, b map[string]any) {
	t.Helper()
	for _, k := range []string{"ok", "effect", "reason", "rule", "policies", "policy_version", "obligations", "approval", "data", "masked", "rows_dropped", "policy_errors"} {
		if Canon(a[k]) != Canon(b[k]) {
			t.Errorf("%s: `%s` differs:\n  go        %s\n  reference %s", what, k, Canon(a[k]), Canon(b[k]))
		}
	}
	pa, _ := a["principal"].(map[string]any)
	pb, _ := b["principal"].(map[string]any)
	if Canon(pa) != Canon(pb) {
		t.Errorf("%s: principal differs:\n  go        %s\n  reference %s", what, Canon(pa), Canon(pb))
	}
}

// a. Tokens issued by one are accepted by the other, role tokens with `grp` included.
func TestInteropTokens(t *testing.T) {
	needPython(t)
	bundle := specBundle(t)
	supervisor := map[string]any{"user": "dave", "agent": "support-bot", "role": "supervisor", "groups": []any{"supervisors", "support", "nope"},
		"task": "escalation-1", "tenant": "t1"}
	largeRefund := func(token any) map[string]any {
		return map[string]any{"token": token, "action": "create", "resource": map[string]any{"path": "billing.refund", "id": "r-9", "attrs": map[string]any{"tenant": "t1"}},
			"context": map[string]any{"spend": map[string]any{"currency": "EUR", "amount": int64(30000)}}, "dry_run": true}
	}
	customer := func(token any) map[string]any {
		return map[string]any{"token": token, "action": "read", "resource": map[string]any{"path": "crm.customer", "id": "c-1"},
			"data": []any{map[string]any{"id": "c-1", "name": "Ada", "ssn": "1", "region": "US", "card": map[string]any{"number": "4111", "last4": "1111"}},
				map[string]any{"id": "c-2", "region": "EU"}}}
	}

	t.Run("go issues, the reference verifies", func(t *testing.T) {
		issuer, _ := newTestEngine(t, map[string]any{"allow_test_clock": false})
		public := issuer.Call("info", map[string]any{})["public_key"]
		verifier := pyConfig(t, "verify.json", map[string]any{"bundle_dir": bundle, "verify_only": true, "trusted_keys": []any{public}})

		plain := mustOK(t, issuer.Call("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap(), "tenant": "t1", "task": "ticket-7"}))
		theirs := pythonCall(t, verifier, "authorize", readRequest(plain["token"]))
		if theirs["effect"] != "allow" || theirs["principal"].(map[string]any)["user"] != "alice" {
			t.Fatalf("the reference does not accept a token issued by the Go port: %s", Canon(theirs))
		}
		sameDecision(t, "plain token", issuer.Call("authorize", readRequest(plain["token"])), theirs)
		inspected := pythonCall(t, verifier, "inspect_token", map[string]any{"token": plain["token"]})
		mine := issuer.Call("inspect_token", map[string]any{"token": plain["token"]})
		if inspected["valid"] != true || Canon(inspected["claims"]) != Canon(mine["claims"]) {
			t.Errorf("claims read by the reference differ:\n  go        %s\n  reference %s", Canon(mine["claims"]), Canon(inspected["claims"]))
		}

		role := mustOK(t, issuer.Call("issue_token", supervisor))
		claims := pythonCall(t, verifier, "inspect_token", map[string]any{"token": role["token"]})["claims"].(map[string]any)
		if claims["role"] != "supervisor" || Canon(claims["grp"]) != `[{"id":"supervisors","type":"Group"},{"id":"support","type":"Group"}]` {
			t.Errorf("role and grp as read by the reference: %s", Canon(claims))
		}
		// dave holds nothing in entities.json: the decision below rests on `grp`
		theirs = pythonCall(t, verifier, "authorize", largeRefund(role["token"]))
		if theirs["effect"] != "allow" || theirs["principal"].(map[string]any)["role"] != "supervisor" {
			t.Errorf("the reference does not honour a role token with grp from the Go port: %s", Canon(theirs))
		}
		sameDecision(t, "role token, large refund", issuer.Call("authorize", largeRefund(role["token"])), theirs)
		sameDecision(t, "role token, filter", issuer.Call("filter", customer(role["token"])), pythonCall(t, verifier, "filter", customer(role["token"])))

		// a sub-agent token keeps role and grp
		child := mustOK(t, issuer.Call("exchange_token", map[string]any{"subject_token": role["token"], "actor": "refund-helper", "ttl": 120}))
		theirs = pythonCall(t, verifier, "filter", customer(child["token"]))
		if theirs["principal"].(map[string]any)["role"] != "supervisor" || Canon(theirs["principal"].(map[string]any)["chain"]) != `["support-bot","refund-helper"]` {
			t.Errorf("child token as read by the reference: %s", Canon(theirs))
		}
		sameDecision(t, "child of a role token", issuer.Call("filter", customer(child["token"])), theirs)

		// a key the reference was not told to trust
		stranger, _ := newTestEngine(t, map[string]any{"allow_test_clock": false})
		foreign := mustOK(t, stranger.Call("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap()}))
		if theirs := pythonCall(t, verifier, "authorize", readRequest(foreign["token"])); theirs["reason"] != "token_invalid" {
			t.Errorf("the reference accepted a token from an untrusted key: %s", Canon(theirs))
		}
	})

	t.Run("the reference issues, go verifies", func(t *testing.T) {
		state := filepath.Join(t.TempDir(), "state")
		issuer := pyConfig(t, "issue.json", map[string]any{"bundle_dir": bundle, "state_dir": state})
		capFile := filepath.Join(t.TempDir(), "cap.json")
		writeJSONFile(t, capFile, fullCap())
		plain := python(t, "token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "@"+capFile, "--tenant", "t1", "--task", "ticket-7", "--raw", "--config", issuer)
		if plain.code != 0 {
			t.Fatalf("reference token issue: %s", plain.stderr)
		}
		verifier, err := NewEngine(map[string]any{"bundle_dir": bundle, "verify_only": true, "trusted_keys": []any{readTrim(t, filepath.Join(state, "signing_key.pub.b64"))}})
		if err != nil {
			t.Fatal(err)
		}
		defer verifier.Close()
		if info := verifier.Call("info", map[string]any{}); info["can_issue"] != false || info["key_id"] != nil {
			t.Errorf("a verify-only engine: %s", Canon(info))
		}
		mine := verifier.Call("authorize", readRequest(plain.stdout))
		if mine["effect"] != "allow" || mine["principal"].(map[string]any)["user"] != "alice" || mine["principal"].(map[string]any)["tenant"] != "t1" {
			t.Fatalf("the Go port does not accept a token issued by the reference: %s", Canon(mine))
		}
		sameDecision(t, "plain token", mine, pythonCall(t, issuer, "authorize", readRequest(plain.stdout)))
		theirs := pythonCall(t, issuer, "inspect_token", map[string]any{"token": plain.stdout})
		if got := verifier.Call("inspect_token", map[string]any{"token": plain.stdout}); Canon(got["claims"]) != Canon(theirs["claims"]) {
			t.Errorf("claims differ:\n  go        %s\n  reference %s", Canon(got["claims"]), Canon(theirs["claims"]))
		}

		role := python(t, "token", "issue", "--user", "dave", "--agent", "support-bot", "--role", "supervisor", "--groups", "supervisors,support,nope",
			"--task", "escalation-1", "--tenant", "t1", "--raw", "--config", issuer)
		if role.code != 0 {
			t.Fatalf("reference role token: %s", role.stderr)
		}
		claims := verifier.Call("inspect_token", map[string]any{"token": role.stdout})["claims"].(map[string]any)
		if claims["role"] != "supervisor" || Canon(claims["grp"]) != `[{"id":"supervisors","type":"Group"},{"id":"support","type":"Group"}]` {
			t.Errorf("role and grp as read by the Go port: %s", Canon(claims))
		}
		mine = verifier.Call("authorize", largeRefund(role.stdout))
		if mine["effect"] != "allow" || mine["principal"].(map[string]any)["role"] != "supervisor" {
			t.Errorf("the Go port does not honour a role token with grp from the reference: %s", Canon(mine))
		}
		sameDecision(t, "role token, large refund", mine, pythonCall(t, issuer, "authorize", largeRefund(role.stdout)))
		sameDecision(t, "role token, filter", verifier.Call("filter", customer(role.stdout)), pythonCall(t, issuer, "filter", customer(role.stdout)))
		if r := verifier.Call("exchange_token", map[string]any{"subject_token": role.stdout, "actor": "refund-helper", "ttl": 60}); errCode(r) != "no_signing_key" {
			t.Errorf("a verify-only engine cannot issue: %s", Canon(r))
		}

		// the same key in both: each delegates from the other's token
		shared, err := NewEngine(map[string]any{"bundle_dir": bundle, "signing_key": readTrim(t, filepath.Join(state, "signing_key.pk8.b64"))})
		if err != nil {
			t.Fatal(err)
		}
		defer shared.Close()
		if a, b := shared.Call("info", map[string]any{}), python(t, "info", "--config", issuer).json(t); a["key_id"] != b["key_id"] || a["public_key"] != b["public_key"] {
			t.Errorf("key id / public key of one private key differ: go %v %v, reference %v %v", a["key_id"], a["public_key"], b["key_id"], b["public_key"])
		}
		child := mustOK(t, shared.Call("exchange_token", map[string]any{"subject_token": role.stdout, "actor": "refund-helper", "ttl": 60,
			"cap": map[string]any{"actions": []any{"read"}, "resources": []any{"crm.customer/c-*"}, "deny_labels": []any{"pii"}, "budget": map[string]any{"EUR": int64(5)}}}))
		grand := python(t, "token", "exchange", "--token", child["token"].(string), "--actor", "summarizer", "--ttl", "30", "--raw", "--config", issuer)
		if grand.code != 0 {
			t.Fatalf("the reference cannot delegate from a Go child token: %s", grand.stdout+grand.stderr)
		}
		got := shared.Call("filter", customer(grand.stdout))
		if Canon(got["principal"].(map[string]any)["chain"]) != `["support-bot","refund-helper","summarizer"]` || got["principal"].(map[string]any)["role"] != "supervisor" {
			t.Errorf("grandchild: %s", Canon(got))
		}
		sameDecision(t, "grandchild", got, pythonCall(t, issuer, "filter", customer(grand.stdout)))

		// not trusted: another engine of this port refuses the reference's token
		stranger, _ := newTestEngine(t, map[string]any{"allow_test_clock": false})
		if r := stranger.Call("authorize", readRequest(plain.stdout)); r["reason"] != "token_invalid" {
			t.Errorf("a token from an untrusted key was accepted: %s", Canon(r))
		}
	})
}

// b. Signed bundles load in the other; both compute the same version.
func TestInteropBundles(t *testing.T) {
	needPython(t)
	if a, b := python(t, "info", "--bundle", specBundle(t)).json(t)["policy_version"], func() any {
		e, _ := newTestEngine(t, nil)
		return e.Call("info", map[string]any{})["policy_version"]
	}(); a != b || a == nil {
		t.Errorf("bundle version: reference %v, go %v", a, b)
	}
	tamper := func(dir string) {
		p := filepath.Join(dir, "entities.json")
		raw, _ := os.ReadFile(p)
		if err := os.WriteFile(p, []byte(strings.Replace(string(raw), `"region": "EU"`, `"region": "US"`, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("go signs, the reference loads", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "bundle")
		copyDir(t, specBundle(t), dir)
		private, public, err := Keygen()
		if err != nil {
			t.Fatal(err)
		}
		signed, err := SignBundle(dir, private)
		if err != nil {
			t.Fatal(err)
		}
		cfg := pyConfig(t, "signed.json", map[string]any{"bundle_dir": dir, "bundle_public_key": public})
		info := python(t, "info", "--config", cfg)
		if info.code != 0 || info.json(t)["bundle_signed_by"] != signed["key_id"] || info.json(t)["policy_version"] != signed["version"] {
			t.Fatalf("the reference does not load a bundle signed by the Go port: %s %s", info.stdout, info.stderr)
		}
		// the Go-generated private key is one the reference can sign with
		keyFile := filepath.Join(t.TempDir(), "go.key")
		if err := os.WriteFile(keyFile, []byte(private), 0o600); err != nil {
			t.Fatal(err)
		}
		goSig := readTrim(t, filepath.Join(dir, "bundle.sig.json"))
		if r := python(t, "bundle", "sign", "--key", keyFile, "--bundle", dir); r.code != 0 || !strings.Contains(r.stdout, signed["version"].(string)) || !strings.Contains(r.stdout, signed["key_id"].(string)) {
			t.Fatalf("the reference cannot sign with a key made by the Go port: %s %s", r.stdout, r.stderr)
		}
		// Ed25519 is deterministic: both must produce the same signature over the same canonical payload
		theirs, _ := ParseJSON([]byte(readTrim(t, filepath.Join(dir, "bundle.sig.json"))))
		mine, _ := ParseJSON([]byte(goSig))
		if Canon(theirs) != Canon(mine) {
			t.Errorf("bundle.sig.json differs:\n  go        %s\n  reference %s", Canon(mine), Canon(theirs))
		}
		tamper(dir)
		if r := python(t, "info", "--config", cfg); r.code == 0 || !strings.Contains(r.stdout+r.stderr, "bundle_signature") {
			t.Errorf("the reference loaded a bundle changed after signing: %s %s", r.stdout, r.stderr)
		}
	})

	t.Run("the reference signs, go loads", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "bundle")
		copyDir(t, specBundle(t), dir)
		prefix := filepath.Join(t.TempDir(), "ref")
		if r := python(t, "bundle", "keygen", prefix); r.code != 0 {
			t.Fatalf("reference keygen: %s", r.stderr)
		}
		sign := python(t, "bundle", "sign", "--key", prefix+".key", "--bundle", dir)
		if sign.code != 0 {
			t.Fatalf("reference sign: %s", sign.stderr)
		}
		public := readTrim(t, prefix+".pub")
		b, err := LoadBundle(dir, public)
		if err != nil {
			t.Fatalf("the Go port does not load a bundle signed by the reference: %v", err)
		}
		if want := "signed bundle version " + b.Version + " with key " + b.SignedBy; sign.stdout != want {
			t.Errorf("version / key id: reference printed %q, go computed %q", sign.stdout, want)
		}
		// signing again with the reference's key in the Go port gives the same file content
		theirs, _ := ParseJSON([]byte(readTrim(t, filepath.Join(dir, "bundle.sig.json"))))
		mine, err := SignBundle(dir, readTrim(t, prefix+".key"))
		if err != nil || Canon(mine) != Canon(theirs) {
			t.Errorf("bundle.sig.json differs (%v):\n  go        %s\n  reference %s", err, Canon(mine), Canon(theirs))
		}
		_, other, _ := Keygen()
		if _, err := LoadBundle(dir, other); err == nil || err.(*EngineError).Code != "bundle_signature" {
			t.Errorf("another key: %v", err)
		}
		tamper(dir)
		if _, err := LoadBundle(dir, public); err == nil || err.(*EngineError).Code != "bundle_signature" {
			t.Errorf("the Go port loaded a bundle changed after signing: %v", err)
		}
	})
}

// c. An audit log written by one passes the other's verification; tampering is detected.
func TestInteropAudit(t *testing.T) {
	needPython(t)
	bundle := specBundle(t)
	edit := func(log string) {
		raw, _ := os.ReadFile(log)
		changed := strings.Replace(string(raw), `"effect":"deny"`, `"effect":"allow"`, 1)
		if changed == string(raw) {
			t.Fatal("nothing to tamper with")
		}
		if err := os.WriteFile(log, []byte(changed), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	odd := map[string]any{"note": "\u00e9\U0001F600 \"quoted\" back\\slash \u2028\u0085\x01\x1f\x7f tab\t", "list": []any{int64(3), int64(-9223372036854775808), true, "x"},
		"\U00010000": map[string]any{"\uffff": int64(1), "a": map[string]any{"__entity": map[string]any{"type": "User", "id": "z"}}}}

	t.Run("go writes, the reference verifies", func(t *testing.T) {
		e, state := newTestEngine(t, map[string]any{"allow_test_clock": false})
		token := issue(t, e, map[string]any{"task": "t\u00e4sk \U0001F600", "tenant": "t\"1"})["token"]
		req := readRequest(token)
		req["context"] = odd
		req["resource"] = map[string]any{"path": "crm.customer", "id": "c-\u00fc", "attrs": map[string]any{"tenant": "t\"1", "tags": []any{"b", "a"}}}
		allowed := mustOK(t, e.Call("authorize", req))
		mustOK(t, e.Call("authorize", map[string]any{"token": "junk", "action": "read", "resource": map[string]any{"path": "crm.customer"}}))
		mustOK(t, e.Call("authorize", spendRequest(token, 15000, 0))) // held for approval
		mustOK(t, e.Call("apply_obligations", map[string]any{"obligations": allowed["obligations"], "data": map[string]any{"id": "c", "ssn": "1"}, "decision_id": allowed["decision_id"]}))
		child := mustOK(t, e.Call("exchange_token", map[string]any{"subject_token": token, "actor": "refund-helper", "ttl": 60}))
		mustOK(t, e.Call("revoke", map[string]any{"token_id": child["token_id"], "by": "tester"}))
		mine := mustOK(t, e.Call("audit_verify", map[string]any{}))
		if mine["records"] != int64(7) {
			t.Fatalf("expected 7 records: %s", Canon(mine))
		}
		cfg := pyConfig(t, "c.json", map[string]any{"bundle_dir": bundle, "state_dir": state})
		theirs := python(t, "audit", "verify", "--config", cfg)
		if theirs.code != 0 || theirs.json(t)["records"] != mine["records"] || theirs.json(t)["head"] != mine["head"] {
			t.Fatalf("the reference does not verify a log written by the Go port: %s %s", theirs.stdout, theirs.stderr)
		}
		edit(filepath.Join(state, "audit.jsonl"))
		if r := python(t, "audit", "verify", "--config", cfg); r.code == 0 || !strings.Contains(r.stdout+r.stderr, "audit_broken") {
			t.Errorf("the reference did not detect the tampering: %s %s", r.stdout, r.stderr)
		}
		if r := e.Call("audit_verify", map[string]any{}); errCode(r) != "audit_broken" {
			t.Errorf("the Go port did not detect the tampering: %s", Canon(r))
		}
	})

	t.Run("the reference writes, go verifies", func(t *testing.T) {
		state := filepath.Join(t.TempDir(), "state")
		cfg := pyConfig(t, "c.json", map[string]any{"bundle_dir": bundle, "state_dir": state})
		issued := pythonCall(t, cfg, "issue_token", map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap(), "task": "t\u00e4sk \U0001F600", "tenant": "t\"1"})
		token := issued["token"]
		if issued["ok"] != true {
			t.Fatalf("reference issue: %s", Canon(issued))
		}
		req := map[string]any{"token": token, "action": "read", "context": odd,
			"resource": map[string]any{"path": "crm.customer", "id": "c-\u00fc", "attrs": map[string]any{"tenant": "t\"1", "tags": []any{"b", "a"}}}}
		allowed := pythonCall(t, cfg, "authorize", req)
		pythonCall(t, cfg, "authorize", map[string]any{"token": "junk", "action": "read", "resource": map[string]any{"path": "crm.customer"}})
		pythonCall(t, cfg, "authorize", map[string]any{"token": token, "action": "create", "resource": map[string]any{"path": "billing.refund", "id": "r-1"},
			"context": map[string]any{"spend": map[string]any{"currency": "EUR", "amount": int64(15000)}}})
		pythonCall(t, cfg, "apply_obligations", map[string]any{"obligations": allowed["obligations"], "data": map[string]any{"id": "c", "ssn": "1"}, "decision_id": allowed["decision_id"]})
		child := pythonCall(t, cfg, "exchange_token", map[string]any{"subject_token": token, "actor": "refund-helper", "ttl": 60})
		pythonCall(t, cfg, "revoke", map[string]any{"token_id": child["token_id"], "by": "tester"})
		theirs := python(t, "audit", "verify", "--config", cfg).json(t)
		if theirs["records"] != int64(7) {
			t.Fatalf("expected 7 records from the reference: %s", Canon(theirs))
		}
		log := filepath.Join(state, "audit.jsonl")
		n, head, err := VerifyAudit(log)
		if err != nil || n != 7 || head != theirs["head"] {
			t.Fatalf("the Go port does not verify a log written by the reference: %d %s %v", n, head, err)
		}
		// an engine of this port opens the reference's state directory and reads the same log
		e, err := NewEngine(map[string]any{"bundle_dir": bundle, "state_dir": state})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		tail := e.Call("audit_tail", map[string]any{"n": 100})
		theirTail := pythonCall(t, cfg, "audit_tail", map[string]any{"n": 100})
		if Canon(tail["records"]) != Canon(theirTail["records"]) || len(tail["records"].([]any)) == 0 {
			t.Errorf("audit_tail differs:\n  go        %s\n  reference %s", Canon(tail["records"]), Canon(theirTail["records"]))
		}
		edit(log)
		if _, _, err := VerifyAudit(log); err == nil || err.(*EngineError).Code != "audit_broken" || !strings.Contains(err.Error(), "line 3") {
			t.Errorf("the Go port did not detect the tampering: %v", err)
		}
		if r := python(t, "audit", "verify", "--config", cfg); r.code == 0 || !strings.Contains(r.stdout+r.stderr, "line 3") {
			t.Errorf("the reference names another line: %s %s", r.stdout, r.stderr)
		}
	})
}

// d. One state directory, one signing key, a Go engine and the reference
// taking turns: one valid audit chain, shared revocations, spend and approvals.
func TestInteropSharedStateDirectory(t *testing.T) {
	needPython(t)
	if !crossProcessLock {
		t.Skip("no cross-process file lock on this platform: a state directory must not be shared")
	}
	state := filepath.Join(t.TempDir(), "state")
	cfg := pyConfig(t, "shared.json", map[string]any{"bundle_dir": specBundle(t), "state_dir": state})
	// the reference creates the directory and the key; the Go engine adopts both
	if r := python(t, "info", "--config", cfg); r.code != 0 {
		t.Fatalf("reference info: %s", r.stderr)
	}
	e, err := NewEngine(map[string]any{"bundle_dir": specBundle(t), "state_dir": state})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if a, b := e.Call("info", map[string]any{})["key_id"], python(t, "info", "--config", cfg).json(t)["key_id"]; a != b {
		t.Fatalf("the two do not use the same signing key: %v %v", a, b)
	}
	records := int64(0)
	spend := func(token any, amount int64) map[string]any {
		r := spendRequest(token, amount, 0)
		delete(r, "now")
		return r
	}
	read := func(token any) map[string]any {
		r := readRequest(token)
		delete(r, "now")
		return r
	}
	goCall := func(op string, in map[string]any) map[string]any { records++; return mustOK(t, e.Call(op, in)) }
	pyCall := func(op string, in map[string]any) map[string]any {
		records++
		r := pythonCall(t, cfg, op, in)
		if r["ok"] != true {
			t.Fatalf("reference %s: %s", op, Canon(r))
		}
		return r
	}

	// spend: 8000 + 8000 of 20000, then nothing more, whoever asks
	root := goCall("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap()})
	if r := pyCall("authorize", spend(root["token"], 8000)); r["effect"] != "allow" {
		t.Fatalf("reference spend 1: %s", Canon(r))
	}
	if r := goCall("authorize", spend(root["token"], 8000)); r["effect"] != "allow" {
		t.Fatalf("go spend 2: %s", Canon(r))
	}
	if r := pyCall("authorize", spend(root["token"], 8000)); r["reason"] != "budget_exceeded" {
		t.Errorf("the reference does not see the Go port's spend: %s", Canon(r))
	}
	if r := goCall("authorize", spend(root["token"], 8000)); r["reason"] != "budget_exceeded" {
		t.Errorf("the Go port does not see the reference's spend: %s", Canon(r))
	}
	if r := goCall("authorize", spend(root["token"], 4000)); r["effect"] != "allow" {
		t.Errorf("exactly the budget is allowed: %s", Canon(r))
	}
	// a child made by the reference spends against the root's limit, which the Go port recorded
	child := pyCall("exchange_token", map[string]any{"subject_token": root["token"], "actor": "refund-helper", "ttl": 120,
		"cap": map[string]any{"actions": []any{"read", "create"}, "resources": []any{"crm.customer/*", "billing.refund/*"}, "budget": map[string]any{"EUR": int64(500)}}})
	if r := goCall("authorize", spend(child["token"], 1)); r["reason"] != "budget_exceeded" {
		t.Errorf("a child cannot spend what the root has spent: %s", Canon(r))
	}
	if r := goCall("authorize", read(child["token"])); r["effect"] != "allow" || Canon(r["principal"].(map[string]any)["chain"]) != `["support-bot","refund-helper"]` {
		t.Errorf("the Go port does not accept a child made by the reference: %s", Canon(r))
	}

	// revocation by the reference is seen by the running Go engine, and the reverse
	pyCall("revoke", map[string]any{"token": root["token"], "by": "reference"})
	if r := goCall("authorize", read(child["token"])); r["reason"] != "token_revoked" {
		t.Errorf("the Go port does not see the reference's revocation: %s", Canon(r))
	}
	second := pyCall("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap()})
	if r := goCall("authorize", read(second["token"])); r["effect"] != "allow" {
		t.Errorf("a token issued by the reference into the shared directory: %s", Canon(r))
	}
	goCall("revoke", map[string]any{"token_id": second["token_id"], "by": "go"})
	if r := pyCall("authorize", read(second["token"])); r["reason"] != "token_revoked" {
		t.Errorf("the reference does not see the Go port's revocation: %s", Canon(r))
	}

	// approval: asked in one, granted in the other, used once
	third := goCall("issue_token", map[string]any{"user": "erin", "agent": "support-bot", "cap": fullCap()})
	held := goCall("authorize", spend(third["token"], 15000))
	approval, _ := held["approval"].(map[string]any)
	if held["reason"] != "approval_required" || approval["id"] == nil {
		t.Fatalf("expected a held request: %s", Canon(held))
	}
	heldToo := pyCall("authorize", spend(third["token"], 15000))
	if Canon(heldToo["approval"]) != Canon(held["approval"]) {
		t.Errorf("approval id differs: go %s, reference %s", Canon(held["approval"]), Canon(heldToo["approval"]))
	}
	pyCall("approve", map[string]any{"approval_id": approval["id"], "by": "bob"})
	if r := e.Call("approvals", map[string]any{}); len(r["pending"].(map[string]any)) != 0 || len(r["granted"].(map[string]any)) != 1 {
		t.Errorf("approvals after the reference approved: %s", Canon(r))
	}
	granted := goCall("authorize", spend(third["token"], 15000))
	if granted["effect"] != "allow" || Canon(granted["obligations"].(map[string]any)["approved"]) != Canon(map[string]any{"id": approval["id"], "by": "bob"}) {
		t.Errorf("the Go port does not use the reference's approval: %s", Canon(granted))
	}
	if r := pyCall("authorize", spend(third["token"], 15000)); r["reason"] != "budget_exceeded" {
		t.Errorf("after the approved spend of 15000 of 20000: %s", Canon(r))
	}
	heldAgain := pyCall("authorize", spend(third["token"], 5000))
	if heldAgain["effect"] != "allow" {
		t.Errorf("5000 more needs no approval and fits the budget: %s", Canon(heldAgain))
	}

	// revoke by user: a user revoked by one is token_revoked in the other, sub-agent tokens included
	erin := goCall("issue_token", map[string]any{"user": "erin", "agent": "support-bot", "cap": fullCap(), "task": "ticket-9"})
	if erin["task"] != "ticket-9" {
		t.Errorf("issue_token result must carry `task`: %s", Canon(erin))
	}
	erinChild := pyCall("exchange_token", map[string]any{"subject_token": erin["token"], "actor": "refund-helper", "ttl": 60})
	if erinChild["task"] != "ticket-9" || erinChild["role"] != nil {
		t.Errorf("the reference's exchange result: task %v, role %v", erinChild["task"], erinChild["role"])
	}
	bobToken := pyCall("issue_token", map[string]any{"user": "bob", "agent": "support-bot", "cap": fullCap()})
	if r := goCall("revoke", map[string]any{"user": "erin", "by": "go"}); r["revoked_user"] != "erin" || r["issued_up_to"] == nil {
		t.Errorf("go revoke user: %s", Canon(r))
	}
	for _, tok := range []any{erin["token"], erinChild["token"], third["token"]} {
		if r := pyCall("authorize", read(tok)); r["reason"] != "token_revoked" || r["principal"].(map[string]any)["user"] != "erin" {
			t.Errorf("the reference does not see the Go port's revocation of a user: %s", Canon(r))
		}
	}
	if r := pyCall("authorize", read(bobToken["token"])); r["effect"] != "allow" {
		t.Errorf("another user's token is unaffected: %s", Canon(r))
	}
	if r := pyCall("revoke", map[string]any{"user": "bob", "by": "reference"}); r["revoked_user"] != "bob" {
		t.Errorf("reference revoke user: %s", Canon(r))
	}
	if r := goCall("authorize", read(bobToken["token"])); r["reason"] != "token_revoked" || r["principal"].(map[string]any)["user"] != "bob" {
		t.Errorf("the Go port does not see the reference's revocation of a user: %s", Canon(r))
	}
	if r := e.Call("exchange_token", map[string]any{"subject_token": bobToken["token"], "actor": "refund-helper", "ttl": 60}); errCode(r) != "token_revoked" {
		t.Errorf("no delegation from a revoked user's token: %s", Canon(r))
	}

	// one chain, valid for both, with every record of both
	mine := e.Call("audit_verify", map[string]any{})
	theirs := python(t, "audit", "verify", "--config", cfg).json(t)
	if mine["ok"] != true || mine["records"] != records || theirs["records"] != records || mine["head"] != theirs["head"] {
		t.Errorf("audit chain after %d operations:\n  go        %s\n  reference %s", records, Canon(mine), Canon(theirs))
	}
	t.Logf("shared state directory: %d operations alternating between the Go engine and the reference, one audit chain of %v records, head %v", records, mine["records"], mine["head"])
	// and the state file is one both still read
	raw, _ := os.ReadFile(filepath.Join(state, "state.json"))
	parsed, perr := ParseJSON(raw)
	ledger, _ := parsed.(map[string]any)["ledger"].(map[string]any)
	if perr != nil || Canon(ledger[root["token_id"].(string)]) != `{"EUR":20000}` || Canon(ledger[third["token_id"].(string)]) != `{"EUR":20000}` {
		t.Errorf("ledger: %s", Canon(ledger))
	}
}

// ---- a long-running reference process -------------------------------------------

type refProcess struct {
	t   *testing.T
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

func startPython(t *testing.T, script string) *refProcess {
	t.Helper()
	cmd := exec.Command("python3", "-c", script)
	cmd.Env = pythonEnv(t)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &refProcess{t: t, cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<20)}
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Wait()
	})
	return p
}

func (p *refProcess) line(text string) string {
	p.t.Helper()
	if _, err := io.WriteString(p.in, text+"\n"); err != nil {
		p.t.Fatalf("writing to the reference: %v", err)
	}
	reply, err := p.out.ReadString('\n')
	if err != nil {
		p.t.Fatalf("reading from the reference: %v (sent %.300s)", err, text)
	}
	return strings.TrimSuffix(reply, "\n")
}

const canonScript = `
import sys, json
from smartdelegate.canon import canon
for line in sys.stdin:
    sys.stdout.write(canon(json.loads(line)) + "\n")
    sys.stdout.flush()
`

// The canonical form is byte-identical to the reference's, on fixed documents
// and on generated ones (key order, escapes, integers, floats).
func TestInteropCanonicalJSON(t *testing.T) {
	needPython(t)
	ref := startPython(t, canonScript)
	fixed := []string{
		`{"b":1,"a":[true,false,null,"x",{"z":{},"y":[]}]}`,
		`{"\ud83d\ude00":1,"\uffff":2,"\ue000":3,"\ud800\udc00":4,"z":5,"Z":6,"":7,"a\u0000":8,"a":9,"\u00e9":10,"e":11,"\u007f":12,"~":13,"\u0080":14,"\u07ff":15,"\u0800":16,"\udbff\udfff":17}`,
		`"\"\\\/\b\f\n\r\t\u0000\u0001\u001f\u007f\u0080\u0085\u00a0\u2028\u2029\ufeff\ufffd\ud834\udd1e"`,
		`[0,-0,1,-1,9007199254740993,-9007199254740993,9223372036854775807,-9223372036854775808,9223372036854775808,-9223372036854775809,340282366920938463463374607431768211456]`,
		`[0.0,-0.0,1.0,1.5,1e15,1e16,1e-4,1e-5,123456789.125,1.7976931348623157e308,5e-324,2.2250738585072014e-308,0.1,1e22,1e23,NaN,Infinity,-Infinity]`,
		` { "a" : { "c" : 1 , "b" : 2 } , "a" : 3 } `,
		`{"k":"line\nbreak","K":"tab\there","k2":"\u00e9\u00c9","1":1,"10":2,"2":3,"-":4,"_":5," ":6}`,
	}
	for _, doc := range fixed {
		v := mustParse(t, doc)
		want := ref.line(strings.ReplaceAll(doc, "\n", " "))
		if got := Canon(v); got != want {
			t.Errorf("canonical form of %s\n  go        %q\n  reference %q", doc, got, want)
		}
	}
	rng := rand.New(rand.NewSource(20240607))
	randomString := func() string {
		var b strings.Builder
		for n := rng.Intn(6); n > 0; n-- {
			switch rng.Intn(6) {
			case 0:
				b.WriteRune(rune(rng.Intn(0x20))) // controls
			case 1:
				b.WriteRune(rune(0x20 + rng.Intn(0x60))) // ASCII
			case 2:
				b.WriteRune(rune(0x80 + rng.Intn(0x780)))
			case 3:
				b.WriteRune(rune(0xE000 + rng.Intn(0x2000))) // top of the BMP, above the surrogates
			case 4:
				b.WriteRune(rune(0x10000 + rng.Intn(0x100000)))
			default:
				b.WriteRune([]rune{'"', '\\', '/', 0x7f, 0x2028, 0xD7FF, 0xFFFD, 0x800}[rng.Intn(8)])
			}
		}
		return b.String()
	}
	var randomValue func(depth int) any
	randomValue = func(depth int) any {
		switch k := rng.Intn(10); {
		case k == 0:
			return nil
		case k == 1:
			return rng.Intn(2) == 0
		case k == 2:
			return int64(rng.Uint64())
		case k == 3:
			return math.Float64frombits(rng.Uint64())
		case k == 4:
			return float64(rng.Intn(2000)-1000) / float64([]int{1, 2, 10, 1000, 1e6}[rng.Intn(5)]) * math.Pow(10, float64(rng.Intn(40)-20))
		case k <= 6 || depth > 3:
			return randomString()
		case k == 7:
			out := []any{}
			for n := rng.Intn(4); n > 0; n-- {
				out = append(out, randomValue(depth+1))
			}
			return out
		default:
			out := map[string]any{}
			for n := rng.Intn(5); n > 0; n-- {
				out[randomString()] = randomValue(depth + 1)
			}
			return out
		}
	}
	const documents = 3000
	mismatches := 0
	for i := 0; i < documents && mismatches < 10; i++ {
		v := randomValue(0)
		mine := Canon(v)
		if f, ok := v.(float64); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
			// a float the reference reads from Go's own shortest form, to compare how each writes it back
			if want := ref.line(strconv.FormatFloat(f, 'e', -1, 64)); mine != want {
				mismatches++
				t.Errorf("float %v: go %s, reference %s", f, mine, want)
			}
			continue
		}
		// the reference must read the Go form as the same value and write the same bytes
		if want := ref.line(mine); mine != want {
			mismatches++
			t.Errorf("document %d\n  go        %q\n  reference %q", i, mine, want)
		}
		if again, err := ParseJSON([]byte(mine)); err != nil || Canon(again) != mine {
			mismatches++
			t.Errorf("document %d does not survive this port's own parser: %q (%v)", i, mine, err)
		}
	}
}

const engineScript = `
import sys, json
from smartdelegate import Engine
engine = None
for line in sys.stdin:
    m = json.loads(line)
    if "new" in m:
        if engine is not None:
            engine.close()
        engine = None
        try:
            engine = Engine(m["new"])
            out = {"ok": True}
        except Exception as e:
            out = {"ok": False, "error": {"code": getattr(e, "code", "crash:" + type(e).__name__)}}
    else:
        try:
            out = engine.call(m["op"], m.get("input"))
        except Exception as e:
            out = {"ok": False, "error": {"code": "crash:" + type(e).__name__}}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
`

// interpolate replaces "$name" (the whole string, any value) and "${name}"
// (inside a string) by saved values.
func interpolate(v any, vars map[string]any) any {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, "$") {
			if val, ok := vars[x[1:]]; ok {
				return val
			}
		}
		if strings.Contains(x, "${") {
			for name, val := range vars {
				if s, ok := val.(string); ok {
					x = strings.ReplaceAll(x, "${"+name+"}", s)
				}
			}
		}
		return x
	case []any:
		out := make([]any, len(x))
		for i, el := range x {
			out[i] = interpolate(el, vars)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, el := range x {
			out[k] = interpolate(el, vars)
		}
		return out
	}
	return v
}

// scrub removes what two correct engines may answer differently: wording,
// random ids (replaced by their order of appearance) and hashes over them.
func scrub(v any, ids map[string]string) any {
	switch x := v.(type) {
	case string:
		if label, ok := ids[x]; ok {
			return label
		}
		return x
	case []any:
		out := make([]any, len(x))
		for i, el := range x {
			out[i] = scrub(el, ids)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, el := range x {
			switch k {
			case "message", "decision_id", "request_hash", "hash", "prev", "head", "version", "implementation":
				continue
			case "detail", "error":
				if _, isText := el.(string); isText {
					continue
				}
			}
			if label, ok := ids[k]; ok {
				k = label // a token id used as a key (the `lim` claim, the ledger)
			}
			out[k] = scrub(el, ids)
		}
		return out
	}
	return v
}

type side struct {
	vars map[string]any
	ids  map[string]string
}

func newSide() *side { return &side{vars: map[string]any{}, ids: map[string]string{}} }

func (s *side) after(step map[string]any, result map[string]any) string {
	for _, k := range []string{"token", "token_id"} {
		if v, ok := result[k].(string); ok {
			if _, seen := s.ids[v]; !seen {
				s.ids[v] = fmt.Sprintf("<%s %d>", k, len(s.ids))
			}
		}
	}
	if save, ok := step["save"].(map[string]any); ok {
		for name, key := range save {
			var cur any = result
			for _, part := range strings.Split(key.(string), ".") {
				m, _ := cur.(map[string]any)
				cur = m[part]
			}
			s.vars[name] = cur
		}
	}
	return Canon(scrub(result, s.ids))
}

// e. The same requests to both engines, most of them malformed, odd or at a
// limit: every result must be the same (codes, reasons, data, obligations,
// audit records; not wording, random ids or hashes over them).
func TestInteropDifferential(t *testing.T) {
	needPython(t)
	gen := exec.Command("python3", filepath.Join(repoRoot(t), "ports", "go", "testdata", "differential_cases.py"))
	gen.Env = pythonEnv(t)
	gen.Stderr = os.Stderr
	raw, err := gen.Output()
	if err != nil {
		t.Fatalf("testdata/differential_cases.py: %v", err)
	}
	doc := mustParse(t, string(raw)).(map[string]any)
	ref := startPython(t, engineScript)
	private, _, err := Keygen()
	if err != nil {
		t.Fatal(err)
	}
	cases, steps, mismatches := 0, 0, 0
	for _, c := range doc["cases"].([]any) {
		tc := c.(map[string]any)
		name := tc["name"].(string)
		extra, _ := tc["config"].(map[string]any)
		config := func(state string) map[string]any {
			cfg := ConformanceConfig(specBundle(t), state, extra)
			cfg["signing_key"] = private
			if v, has := extra["state_dir"]; has && v == nil {
				delete(cfg, "state_dir")
			}
			return cfg
		}
		dir := t.TempDir()
		e, err := NewEngine(config(filepath.Join(dir, "go")))
		started := mustParse(t, ref.line(Canon(map[string]any{"new": config(filepath.Join(dir, "reference"))}))).(map[string]any)
		if err != nil || started["ok"] != true {
			t.Fatalf("%s: engines did not start: go %v, reference %s", name, err, Canon(started))
		}
		cases++
		mine, theirs := newSide(), newSide()
		for n, s := range tc["steps"].([]any) {
			step := s.(map[string]any)
			op := step["op"].(string)
			input := func(sd *side) any {
				in := interpolate(step["input"], sd.vars)
				if m, ok := in.(map[string]any); ok {
					if _, has := m["now"]; !has {
						m["now"] = testNow
					}
				}
				return in
			}
			goIn := input(mine)
			a := mine.after(step, e.Call(op, goIn))
			reply := ref.line(Canon(map[string]any{"op": op, "input": input(theirs)}))
			parsed, perr := ParseJSON([]byte(reply))
			result, ok := parsed.(map[string]any)
			if perr != nil || !ok {
				t.Fatalf("%s, step %d: the reference answered %q", name, n, reply)
			}
			b := theirs.after(step, result)
			steps++
			if a != b {
				mismatches++
				if mismatches <= 15 {
					t.Errorf("%s, step %d: %s %.600s\n  go        %.1500s\n  reference %.1500s", name, n, op, Canon(goIn), a, b)
				}
			}
		}
		e.Close()
	}
	if mismatches > 15 {
		t.Errorf("... and %d more mismatches", mismatches-15)
	}
	if cases < 15 || steps < 2000 {
		t.Errorf("expected at least 15 cases and 2000 steps, ran %d and %d", cases, steps)
	}
	t.Logf("differential against the reference: %d cases, %d steps, %d mismatches", cases, steps, mismatches)
}
