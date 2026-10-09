// Package smartdelegate is a native Go port of the SmartDelegate engine:
// identity and access management for LLM agents.
//
// One Engine issues and exchanges capability tokens, answers authorization
// requests, applies field obligations and writes the audit log. The Python
// package (src/sf_smartdelegate) is the reference; spec/conformance defines the
// behaviour and this port is held to it.
//
// Decision order for `authorize` / `filter` (first failure wins, default deny):
//
//  1. token: signature, issuer, expiry, revocation (own id and every ancestor)
//  2. catalog: the resource path must be known
//  3. tenant: token tenant must equal the resource tenant, when both exist
//  4. capability: the token's `cap` must cover the action and the resource
//  5. policy: Cedar, forbid overrides permit, an erroring forbid denies
//  6. obligations from the permits that decided: row filter, rate limit
//  7. budget: `context.spend` against every token in the delegation chain
//  8. human approval, last so nobody is asked to approve a doomed request
//  9. fields: capability deny lists, then policy per field (default deny)
//  10. strict mode (inputs): any denied field present in the data denies
package smartdelegate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Version is the SmartDelegate specification version this port implements.
const Version = "0.3.0"

// Implementation is the name this port reports in `info`.
const Implementation = "go"

// space is what the reference's pattern engine calls whitespace.
const space = `[\s\x{1c}-\x{1f}\x{85}\p{Z}]`

var (
	columnRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	rateRe   = regexp.MustCompile(`^` + space + `*(\p{Nd}+)` + space + `*/` + space + `*(\p{Nd}+)` + space + `*$`)
)

type principal struct {
	user      string
	chain     []string
	tenant    any // string, or nil; a token from a trusted key may carry anything
	task      any
	jti       string
	hasJTI    bool
	anc       []string
	cap       *Cap
	exp       int64
	role      any   // string or nil
	groups    []any // live membership [{type, id}] that replaces entities.json for this user
	hasGroups bool
	lim       map[string]any // ancestor token id -> its budget, carried by the token
}

func (p *principal) leaf() string {
	if len(p.chain) == 0 {
		return ""
	}
	return p.chain[len(p.chain)-1]
}

func (p *principal) tokenID() any {
	if p.hasJTI {
		return p.jti
	}
	return nil
}

func (p *principal) toJSON() map[string]any {
	return map[string]any{"user": p.user, "agent": p.leaf(), "chain": strList(p.chain), "tenant": p.tenant,
		"task": p.task, "role": p.role, "token_id": p.tokenID()}
}

func principalOf(claims map[string]any) *principal {
	c, err := capFromJSON(claims["cap"])
	if err != nil {
		panic(err)
	}
	p := &principal{user: userOf(claims), chain: chainOf(claims), tenant: claims["tnt"], task: claims["task"],
		jti: claims["jti"].(string), hasJTI: true, cap: c, exp: claims["exp"].(int64), role: claims["role"]}
	if truthy(claims["anc"]) {
		for _, a := range claims["anc"].([]any) {
			p.anc = append(p.anc, a.(string))
		}
	}
	if g, has := claims["grp"]; has {
		p.groups, p.hasGroups = g.([]any), true
	}
	p.lim, _ = claims["lim"].(map[string]any)
	return p
}

type rateRule struct {
	key           string
	limit, window any // int64, or *big.Int beyond 64 bits
}

type outcome struct {
	allow       bool
	reason      string
	detail      string
	policies    []string
	principal   *principal
	mask        *fieldMask
	fieldAllow  []string
	fieldDeny   []string
	fieldRedact []string
	rowFilter   []map[string]any
	rate        []rateRule
	rateLimit   map[string]any
	approval    map[string]any
	approvedID  string
	approvedBy  any
	approved    bool
	spendCur    string
	spendAmount int64
	spend       bool
	errors      []any
	trace       []any
}

// str is a non-empty string value of an object, or ("", false).
func str(v any, key string) (string, bool) {
	m, _ := v.(map[string]any)
	s, ok := m[key].(string)
	return s, ok && s != ""
}

func strOrNil(v any, key string) any {
	if s, ok := str(v, key); ok {
		return s
	}
	return nil
}

func req(v any, key string) string {
	s, ok := str(v, key)
	if !ok {
		throw("invalid_input", "'"+key+"' is required")
	}
	return s
}

// integer reads an integer option. An integer outside 64 bits is clamped.
func integer(m map[string]any, key string, def int64) int64 {
	switch x := m[key].(type) {
	case int64:
		return x
	case *big.Int:
		if x.Sign() > 0 {
			return 1<<63 - 1
		}
		return -1 << 63
	}
	return def
}

func entity(typ, id string) Entity {
	if !validType(typ) {
		throw("invalid_input", "'"+typ+"' is not a valid entity type")
	}
	return Entity{typ, id}
}

func lookup(root any, dotted string) (any, bool) {
	cur := root
	for _, part := range strings.Split(dotted, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// decimal reads an optional "-" and decimal digits. Like the reference it
// takes the decimal digits of any script. The value is an int64, or a
// *big.Int when it does not fit. ok is false when s is not such a number.
func decimal(s string) (value any, ok bool) {
	digits := strings.TrimPrefix(s, "-")
	if digits == "" {
		return nil, false
	}
	var ascii strings.Builder
	ascii.WriteString(s[:len(s)-len(digits)])
	for _, r := range digits {
		d, isDigit := digitValue(r)
		if !isDigit {
			return nil, false
		}
		ascii.WriteByte(byte('0' + d))
	}
	if n, err := strconv.ParseInt(ascii.String(), 10, 64); err == nil {
		return n, true
	}
	b, _ := new(big.Int).SetString(ascii.String(), 10)
	return b, b != nil
}

// digitValue is the value of a decimal digit (Unicode category Nd). Every
// run of such digits in Unicode starts at a zero and is a multiple of ten long.
func digitValue(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	for _, rg := range unicode.Nd.R16 {
		if rune(rg.Lo) <= r && r <= rune(rg.Hi) {
			return int(r-rune(rg.Lo)) % 10, true
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if rune(rg.Lo) <= r && r <= rune(rg.Hi) {
			return int(r-rune(rg.Lo)) % 10, true
		}
	}
	return 0, false
}

func isDecimal(s string) bool {
	_, ok := decimal(s)
	return ok
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if _, ok := digitValue(r); !ok {
			return false
		}
	}
	return true
}

// parseRowFilter reads `column == context.key`, `column == "literal"`,
// `column == 42`, joined by `&&`.
func parseRowFilter(expr string, ctx map[string]any) []map[string]any {
	var out []map[string]any
	for _, clause := range strings.Split(expr, "&&") {
		lhs, rhs, found := strings.Cut(clause, "==")
		lhs, rhs = strip(lhs), strip(rhs)
		if !found || !columnRe.MatchString(lhs) {
			panic(&deny{code: "policy_error", detail: "row_filter clause '" + strip(clause) + "' is not `column == value`"})
		}
		var value any
		switch {
		case strings.HasPrefix(rhs, "context."):
			v, ok := lookup(ctx, rhs[8:])
			switch v.(type) {
			case map[string]any, []any, float64, nil:
				ok = false
			}
			if !ok {
				panic(&deny{code: "obligation_unresolved", detail: "row filter needs " + rhs + ", which the request did not supply"})
			}
			value = v
		case len(rhs) >= 2 && rhs[0] == '"' && rhs[len(rhs)-1] == '"':
			value = rhs[1 : len(rhs)-1]
		case isDecimal(rhs):
			value, _ = decimal(rhs)
		default:
			panic(&deny{code: "policy_error", detail: "row_filter value '" + rhs + "' is not context.<key>, a quoted string or an integer"})
		}
		out = append(out, map[string]any{"column": lhs, "op": "eq", "value": value})
	}
	return out
}

// parseRate reads "<count>/<seconds>". The numbers are int64, or *big.Int
// when they do not fit (such a limit is never reached).
func parseRate(expr string) (limit, window any, ok bool) {
	m := rateRe.FindStringSubmatch(expr)
	if m == nil {
		return nil, nil, false
	}
	limit, ok1 := decimal(m[1])
	window, ok2 := decimal(m[2])
	if !ok1 || !ok2 || window == int64(0) {
		return nil, nil, false
	}
	return limit, window, true
}

// clamp is an integer as an int64; one that does not fit becomes the largest.
func clamp(v any) int64 {
	if n, ok := v.(int64); ok {
		return n
	}
	return 1<<63 - 1
}

type idpConfig struct {
	issuer, audience, userClaim, groupsClaim, groupType string
	jwksFile                                            string // "" when the keys were given inline
	jwks                                                any
	groupMap                                            map[string]any // nil: names are used as they are
}

// Engine decides, issues and records. One engine is safe to share between
// goroutines; calls are serialised. Engines in different processes that share
// a state directory are serialised by a lock file in it.
type Engine struct {
	mu sync.Mutex

	bundleDir       string
	stateDir        string
	issuer          string
	shadow          bool
	trustChain      bool
	testClock       bool
	bundlePublicKey string
	maxTTL          int64
	defaultTTL      int64
	maxDepth        int64
	approvalTTL     int64
	requireRole     bool
	idp             *idpConfig

	bundle   *Bundle
	keys     *keyring
	lock     *os.File
	state    *state
	audit    *auditLog
	rate     map[string][]int64
	counter  uint64
	closed   bool
	pidLabel string
}

// NewEngine builds an engine from a configuration object; see spec/API.md.
// The error is an *EngineError.
func NewEngine(config map[string]any) (e *Engine, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e != nil {
				e.Close()
			}
			e, err = nil, asEngineError(r)
		}
	}()
	e = &Engine{rate: map[string][]int64{}, pidLabel: strconv.Itoa(os.Getpid())}
	e.init(config)
	return e, nil
}

func asEngineError(r any) *EngineError {
	switch x := r.(type) {
	case *EngineError:
		return x
	case *deny:
		return newErr("internal", "deny outside a decision: "+x.code)
	case error:
		return newErr("internal", fmt.Sprintf("%T: %v", x, x))
	}
	return newErr("internal", fmt.Sprint(r))
}

func (e *Engine) init(config map[string]any) {
	if config == nil {
		throw("invalid_input", "config must be an object")
	}
	n, nerr := normalize(config, 0)
	if nerr != nil {
		throw("invalid_input", "config: "+nerr.Error())
	}
	c := n.(map[string]any)
	e.bundleDir = req(c, "bundle_dir")
	e.stateDir, _ = str(c, "state_dir")
	e.issuer = "smartdelegate://local"
	if s, ok := str(c, "issuer"); ok {
		e.issuer = s
	}
	if mode, ok := str(c, "mode"); ok {
		if mode != "enforce" && mode != "shadow" {
			throw("invalid_config", "mode must be 'enforce' or 'shadow'")
		}
		e.shadow = mode == "shadow"
	}
	e.trustChain = c["trust_caller_chain"] == true
	e.testClock = c["allow_test_clock"] == true
	e.bundlePublicKey, _ = str(c, "bundle_public_key")
	e.maxTTL = integer(c, "max_ttl", 3600)
	e.defaultTTL = integer(c, "default_ttl", 900)
	e.maxDepth = integer(c, "max_depth", 4)
	e.approvalTTL = integer(c, "approval_ttl", 900)
	e.requireRole = c["require_role"] == true
	if idp, ok := c["idp"].(map[string]any); ok {
		var jwks any = idp["jwks"]
		jwksFile := ""
		if _, isMap := jwks.(map[string]any); !isMap {
			jwksFile = req(idp, "jwks_file")
			raw, err := os.ReadFile(jwksFile)
			if err != nil {
				throw("invalid_config", "jwks_file: "+err.Error())
			}
			if jwks, err = ParseJSON(raw); err != nil {
				throw("invalid_config", "jwks_file: "+err.Error())
			}
		}
		var gmap map[string]any
		if raw := idp["group_map"]; raw != nil {
			m, ok := raw.(map[string]any)
			for _, v := range m {
				if _, isStr := v.(string); !isStr {
					ok = false
				}
			}
			if !ok {
				throw("invalid_config", "idp.group_map must map a claim value to a group id")
			}
			gmap = m
		}
		gtype := "Group"
		if s, ok := str(idp, "group_type"); ok {
			gtype = s
		}
		if !validType(gtype) {
			throw("invalid_config", "idp.group_type is not a valid entity type")
		}
		e.idp = &idpConfig{issuer: req(idp, "issuer"), audience: req(idp, "audience"), jwks: jwks, jwksFile: jwksFile, userClaim: "sub", groupType: gtype, groupMap: gmap}
		if s, ok := str(idp, "user_claim"); ok {
			e.idp.userClaim = s
		}
		e.idp.groupsClaim, _ = str(idp, "groups_claim")
	}

	b, berr := loadBundle(e.bundleDir, e.bundlePublicKey)
	if berr != nil {
		panic(berr)
	}
	e.bundle = b
	if e.stateDir != "" {
		if err := os.MkdirAll(e.stateDir, 0o755); err != nil {
			throw("state_io", e.stateDir+": "+ioMessage(err))
		}
		f, err := os.OpenFile(filepath.Join(e.stateDir, "lock"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			throw("state_io", "cannot open the state directory lock: "+ioMessage(err))
		}
		e.lock = f
	}

	unlock := e.acquire()
	defer unlock()
	private := ""
	switch {
	case c["verify_only"] == true:
	case hasStr(c, "signing_key"):
		private = c["signing_key"].(string)
	case e.stateDir != "":
		private = e.stateKey()
	default:
		var err error
		if private, _, err = Keygen(); err != nil {
			throw("crypto", err.Error())
		}
	}
	var trusted []string
	switch t := c["trusted_keys"].(type) {
	case []any:
		for _, k := range t {
			if s, ok := k.(string); ok {
				trusted = append(trusted, s)
			}
		}
	case string:
		if t != "" {
			throw("crypto", "trusted_keys must be a list of base64 public keys")
		}
	}
	keys, kerr := newKeyring(private, trusted)
	if kerr != nil {
		panic(kerr)
	}
	e.keys = keys
	st, serr := newState(e.stateDir)
	if serr != nil {
		panic(serr)
	}
	e.state = st
	if e.stateDir != "" && c["audit"] != false {
		e.audit = newAuditLog(filepath.Join(e.stateDir, "audit.jsonl"))
	}
}

func hasStr(m map[string]any, key string) bool {
	_, ok := str(m, key)
	return ok
}

// keyWait is how long an empty signing key file is given to fill.
var keyWait = 30 * time.Second

// readKey reads the signing key file. An empty file means another process is
// still writing it: wait for the content. An empty key is never read as "no
// key", which would silently turn an issuer into a verify-only engine.
func readKey(kp string) string {
	deadline := time.Now().Add(keyWait)
	for {
		raw, err := os.ReadFile(kp)
		if err != nil {
			throw("state_io", kp+": "+ioMessage(err))
		}
		if !utf8.Valid(raw) {
			throw("state_io", kp+": not UTF-8")
		}
		if text := strip(string(raw)); text != "" {
			return text
		}
		if time.Now().After(deadline) {
			throw("state_io", kp+" is empty")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stateKey reads the signing key of the state directory, creating it on first
// use. Two engines can start on an empty state directory at once, so the key
// is written to a private temporary file and hard-linked into place: the link
// either creates the key or fails because the other engine already did, and
// nobody reads half a key.
func (e *Engine) stateKey() string {
	kp := filepath.Join(e.stateDir, "signing_key.pk8.b64")
	if _, err := os.Stat(kp); err == nil {
		return readKey(kp)
	}
	private, public, err := Keygen()
	if err != nil {
		throw("crypto", err.Error())
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		throw("crypto", "no randomness: "+err.Error())
	}
	tmp := filepath.Join(e.stateDir, fmt.Sprintf(".signing_key.%d.%s.tmp", os.Getpid(), hex.EncodeToString(suffix)))
	writeNew := func(path string) error {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, werr := f.WriteString(private)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		return werr
	}
	if err := writeNew(tmp); err != nil {
		throw("state_io", kp+": "+ioMessage(err))
	}
	defer os.Remove(tmp)
	err = os.Link(tmp, kp)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		// a file system without hard links: fall back to exclusive create
		err = writeNew(kp)
	}
	if errors.Is(err, fs.ErrExist) {
		return readKey(kp) // another process created it first
	}
	if err != nil {
		throw("state_io", kp+": "+ioMessage(err))
	}
	if err := os.WriteFile(filepath.Join(e.stateDir, "signing_key.pub.b64"), []byte(public), 0o644); err != nil {
		throw("state_io", ioMessage(err))
	}
	return private
}

// ---- plumbing ------------------------------------------------------------------

// acquire takes the engine mutex and the state-directory lock; the returned
// function releases both.
func (e *Engine) acquire() func() {
	e.mu.Lock()
	if e.lock != nil {
		if err := lockFile(e.lock); err != nil {
			e.mu.Unlock()
			throw("state_io", "cannot lock the state directory: "+err.Error())
		}
	}
	return func() {
		if e.lock != nil {
			_ = unlockFile(e.lock)
		}
		e.mu.Unlock()
	}
}

// Close releases the state-directory lock file. An engine with a state
// directory refuses calls after Close.
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lock != nil {
		e.closed = true
		_ = e.lock.Close()
		e.lock = nil
	}
}

// Call runs one operation of spec/API.md: JSON in, JSON out. It never panics
// and never returns an error value; a request that cannot be processed comes
// back as {"ok": false, "error": {"code", "message", "rule"}}.
//
// payload is a JSON object: map[string]any holding nil, bool, string,
// integers (any Go integer type, json.Number, *big.Int), []any and
// map[string]any. A float64 is a float and is rejected where floats are not
// allowed, so decode request bodies with ParseJSON or CallJSON, not with
// encoding/json's default float64 numbers.
func (e *Engine) Call(op string, payload any) (result map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			// a bug must surface as a refusal, never as an allow or a crash
			result = asEngineError(r).Result()
		}
	}()
	input, nerr := normalize(payload, 0)
	if errors.Is(nerr, errTooDeep) {
		throw("invalid_input", "the request is nested too deeply")
	}
	unlock := e.acquire()
	defer unlock()
	if e.closed {
		throw("state_io", "the engine is closed")
	}
	i, ok := input.(map[string]any)
	if nerr != nil || !ok {
		throw("invalid_input", "the request body must be a JSON object")
	}
	if err := e.state.refresh(); err != nil {
		panic(err)
	}
	out := e.dispatch(op, i)
	out["ok"] = true
	n, nerr := normalize(out, 0) // a copy: nothing the caller holds aliases engine state
	if nerr != nil {
		panic(nerr)
	}
	return n.(map[string]any)
}

// CallJSON is Call for a JSON request body; it returns the JSON result.
func (e *Engine) CallJSON(op string, input []byte) []byte {
	v, err := parseJSONBytes(input)
	if err != nil {
		return MarshalJSON(newErr("invalid_input", "the request body is not JSON: "+err.Error()).Result())
	}
	return MarshalJSON(e.Call(op, v))
}

func (e *Engine) dispatch(op string, i map[string]any) map[string]any {
	switch op {
	case "authorize":
		return e.decide(i, false)
	case "filter":
		return e.decide(i, true)
	case "explain":
		j := make(map[string]any, len(i)+2)
		for k, v := range i {
			j[k] = v
		}
		j["explain"], j["dry_run"] = true, true
		_, withData := i["data"]
		return e.decide(j, withData)
	case "issue_token":
		return e.issueToken(i)
	case "exchange_token":
		return e.exchangeToken(i)
	case "inspect_token":
		return e.inspectToken(i)
	case "apply_obligations":
		return e.applyObligations(i)
	case "revoke":
		return e.revoke(i)
	case "approve":
		return e.approve(i)
	case "approvals":
		return map[string]any{"pending": e.state.data["pending"], "granted": e.state.data["approvals"]}
	case "audit_verify":
		if e.audit == nil {
			throw("no_audit", "this engine has no audit log (no state_dir, or audit is off)")
		}
		if !exists(e.audit.path) {
			return map[string]any{"records": int64(0), "head": genesis}
		}
		n, head := verifyAudit(e.audit.path)
		return map[string]any{"records": n, "head": head}
	case "audit_tail":
		if e.audit == nil {
			throw("no_audit", "this engine has no audit log")
		}
		return map[string]any{"records": auditTail(e.audit.path, integer(i, "n", 20))}
	case "info":
		return e.info()
	case "reload":
		// a bundle that fails to load leaves the old one in force
		b, err := loadBundle(e.bundleDir, e.bundlePublicKey)
		if err != nil {
			panic(err)
		}
		// the provider's signing keys are re-read too, so a key rotation
		// needs a reload, not a restart; a file that fails to load leaves the
		// old keys (and the old bundle) in force
		if e.idp != nil && e.idp.jwksFile != "" {
			raw, rerr := os.ReadFile(e.idp.jwksFile)
			if rerr != nil {
				throw("invalid_config", "jwks_file: "+rerr.Error())
			}
			parsed, perr := ParseJSON(raw)
			if perr != nil {
				throw("invalid_config", "jwks_file: "+perr.Error())
			}
			jwks, _ := parsed.(map[string]any)
			if _, isList := jwks["keys"].([]any); !isList {
				throw("invalid_config", "jwks_file: expected {\"keys\": [...]}")
			}
			e.idp.jwks = jwks
		}
		e.bundle = b
		e.record(map[string]any{"event": "bundle_reloaded", "policy_version": e.bundle.Version}, time.Now().Unix())
		return e.info()
	}
	throw("unknown_op", "no operation named '"+op+"'")
	return nil
}

func orNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (e *Engine) info() map[string]any {
	resources := sortedKeys(e.bundle.catalog)
	roles := sortedKeys(e.bundle.Roles)
	mode := "enforce"
	if e.shadow {
		mode = "shadow"
	}
	var oidc any
	if e.idp != nil {
		oidc = e.idp.issuer
	}
	return map[string]any{"version": Version, "implementation": Implementation, "policy_version": e.bundle.Version,
		"bundle_signed_by": orNil(e.bundle.SignedBy), "policies": int64(len(e.bundle.Policies)),
		"resources": strList(resources), "roles": strList(roles), "mode": mode,
		"issuer": e.issuer, "key_id": orNil(e.keys.kid), "public_key": orNil(e.keys.publicB64),
		"can_issue": e.keys.canSign(), "oidc": oidc}
}

func (e *Engine) now(i map[string]any) int64 {
	if n, ok := i["now"]; ok && e.testClock && isInt(n) {
		return integer(i, "now", 0)
	}
	return time.Now().Unix()
}

// record writes an audit record. Fail closed: when the decision cannot be
// recorded, the operation fails and the caller gets an error instead of an allow.
func (e *Engine) record(rec map[string]any, ts int64) {
	if e.audit == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			if ee, ok := r.(*EngineError); ok {
				panic(newErr("audit_io", "the decision could not be recorded, so it is refused: "+ee.Message))
			}
			panic(r)
		}
	}()
	e.audit.append(rec, ts)
}

// ---- tokens ------------------------------------------------------------------------

// verifyToken panics with *deny; `claims` is attached when the signature was
// good, so an expired or revoked token's denial can still be attributed.
func (e *Engine) verifyToken(token string, now int64) map[string]any {
	claims, err := e.keys.verify(token, e.issuer)
	if err != nil {
		panic(&deny{code: "token_invalid", detail: err.Error()})
	}
	if len(chainOf(claims)) == 0 {
		panic(&deny{code: "token_invalid", detail: "the token names no agent"})
	}
	exp, iat := claims["exp"].(int64), claims["iat"].(int64)
	switch {
	case exp <= now:
		panic(&deny{code: "token_expired", detail: "the capability token has expired", claims: claims})
	case iat > satAdd(now, 60):
		panic(&deny{code: "token_invalid", detail: "the capability token is dated in the future", claims: claims})
	}
	revoked := e.state.section("revoked")
	ids := append(append([]any{}, claims["anc"].([]any)...), claims["jti"])
	for _, tid := range ids {
		if _, gone := revoked[tid.(string)]; gone {
			panic(&deny{code: "token_revoked", detail: "token " + tid.(string) + " in the delegation chain was revoked", claims: claims})
		}
	}
	// offboarding: every token of this user issued up to the cut-off is dead
	cut := false
	switch cutoff := e.state.section("revoked_users")[userOf(claims)].(type) {
	case int64:
		cut = iat <= cutoff
	case *big.Int:
		cut = cutoff.Sign() > 0
	}
	if cut {
		panic(&deny{code: "token_revoked", detail: "every token issued for this user up to the cut-off was revoked", claims: claims})
	}
	return claims
}

func orEmpty(v any) any {
	if truthy(v) {
		return v
	}
	return ""
}

func (e *Engine) iamContext(p *principal) map[string]any {
	attrs, ok := e.bundle.attrs["User::"+p.user]
	if !ok {
		attrs = map[string]any{}
	}
	root := ""
	if len(p.chain) > 0 {
		root = p.chain[0]
	}
	return map[string]any{
		"user_attrs": attrs,
		"user":       map[string]any{"__entity": map[string]any{"type": "User", "id": p.user}},
		"user_id":    p.user,
		"chain":      strList(p.chain),
		"depth":      int64(len(p.chain)),
		"root_agent": map[string]any{"__entity": map[string]any{"type": "Agent", "id": root}},
		"tenant":     orEmpty(p.tenant),
		"task":       orEmpty(p.task),
		"role":       orEmpty(p.role),
	}
}

// storeFor is the entity store this principal is judged against. A token that
// carries live group membership replaces what entities.json says about that
// user; everything else is unchanged.
func (e *Engine) storeFor(p *principal) *Store {
	if !p.hasGroups {
		return e.bundle.store
	}
	parents := make([]Entity, len(p.groups))
	for i, g := range p.groups {
		gm := g.(map[string]any)
		parents[i] = Entity{gm["type"].(string), gm["id"].(string)}
	}
	return e.bundle.store.withParents(Entity{"User", p.user}, parents)
}

// groups normalises group membership supplied at issuance: names or {type,
// id}. Groups that entities.json does not define are dropped; the result is
// sorted and free of duplicates, so every port writes the same claim.
func (e *Engine) groups(raw any, defaultType string, mapping map[string]any) ([]any, *EngineError) {
	bad := newErr("invalid_input", "groups must be a list of group names or {type, id}")
	if s, ok := raw.(string); ok {
		raw = []any{s}
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, bad
	}
	seen := map[Entity]bool{}
	for _, g := range list {
		var ent Entity
		switch x := g.(type) {
		case string:
			if mapping != nil {
				mapped, has := mapping[x]
				if !has {
					continue
				}
				x = mapped.(string)
			}
			ent = Entity{defaultType, x}
		case map[string]any:
			t, okT := x["type"].(string)
			id, okID := x["id"].(string)
			if !okT || !okID {
				return nil, bad
			}
			ent = Entity{t, id}
		default:
			return nil, bad
		}
		if validType(ent.Type) && e.bundle.store.has(ent) {
			seen[ent] = true
		}
	}
	ents := make([]Entity, 0, len(seen))
	for ent := range seen {
		ents = append(ents, ent)
	}
	sort.Slice(ents, func(a, b int) bool {
		if ents[a].Type != ents[b].Type {
			return ents[a].Type < ents[b].Type
		}
		return ents[a].ID < ents[b].ID
	})
	out := make([]any, len(ents))
	for i, ent := range ents {
		out[i] = map[string]any{"type": ent.Type, "id": ent.ID}
	}
	return out, nil
}

func anyMatch(patterns []string, s string) bool {
	for _, p := range patterns {
		if patternMatches(p, s) {
			return true
		}
	}
	return false
}

func sortedUnion(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	return sortedKeys(set)
}

// applyRole: the human lends the agent one of their roles for this task. It
// returns the capability and lifetime the token gets, and fails when the
// human does not hold the role or asks for more than the role allows.
func (e *Engine) applyRole(name string, p *principal, c *Cap, ttl int64) (*Cap, int64) {
	role := e.bundle.Roles[name]
	if role == nil {
		throw("unknown_role", "roles.json defines no role named '"+name+"'")
	}
	user := Entity{"User", p.user}
	held := e.storeFor(p).ancestorsOf(user)
	holds := false
	for _, m := range role.Members {
		holds = holds || m == user || held[m]
	}
	if !holds {
		throw("role_not_held", "user '"+p.user+"' does not hold the role '"+name+"'")
	}
	if role.Agents != nil && !anyMatch(role.Agents, p.leaf()) {
		throw("role_exceeded", "agent '"+p.leaf()+"' may not be started in the role '"+name+"'")
	}
	if role.Tasks != nil {
		task, _ := p.task.(string)
		if task == "" || !anyMatch(role.Tasks, task) {
			throw("role_exceeded", "the role '"+name+"' covers only tasks matching: "+strings.Join(role.Tasks, ", "))
		}
	}
	if c == nil {
		c = role.Cap.clone()
	} else {
		// what the role never sees, the token never sees
		c.DenyLabels = sortedUnion(c.DenyLabels, role.Cap.DenyLabels)
		c.DenyFields = sortedUnion(c.DenyFields, role.Cap.DenyFields)
		if err := c.checkNarrowerThan(role.Cap); err != nil {
			throw("role_exceeded", "more than the role '"+name+"' allows: "+err.Message)
		}
	}
	if role.MaxTTL != 0 && role.MaxTTL < ttl {
		ttl = role.MaxTTL
	}
	return c, ttl
}

type verdict struct {
	allow       bool
	policies    []string
	errors      []any
	forbidError bool
}

func (e *Engine) evaluate(who Entity, action string, resource Entity, ctx map[string]any, store *Store) verdict {
	r := IsAuthorized(e.bundle.Policies, &Env{Principal: who, Action: entity("Action", action), Resource: resource, Context: ctx, Store: store})
	v := verdict{policies: r.Reasons}
	for _, pe := range r.Errors {
		effect := "permit"
		if !e.bundle.Policies[pe.ID].Permit {
			effect, v.forbidError = "forbid", true
		}
		v.errors = append(v.errors, map[string]any{"policy": pe.ID, "effect": effect, "error": pe.Message})
	}
	v.allow = r.Allow && !v.forbidError
	return v
}

// checkDelegation: is `delegator` allowed to hand `cap` to `agent`? Governed
// by the same policies as everything else: action "delegate" on the Agent.
func (e *Engine) checkDelegation(delegator Entity, agent string, p *principal, c *Cap, ttl int64) {
	agentUID := entity("Agent", agent)
	if !e.bundle.store.has(agentUID) {
		throw("unknown_agent", "agent '"+agent+"' is not registered in entities.json")
	}
	ctx, err := fromJSON(map[string]any{"iam": e.iamContext(p),
		"requested": map[string]any{"actions": strList(c.Actions), "resources": strList(c.Resources), "ttl": ttl, "budget": c.budgetJSON()}})
	if err != nil {
		throw("invalid_input", err.Error())
	}
	v := e.evaluate(delegator, "delegate", agentUID, ctx.(map[string]any), e.storeFor(p))
	if !v.allow {
		why := "no policy permits it"
		if len(v.policies) > 0 {
			why = "forbidden by " + strings.Join(v.policies, ", ")
		}
		throw("delegation_denied", delegator.String()+" may not delegate to agent '"+agent+"': "+why)
	}
}

func parseCap(i map[string]any) *Cap {
	if i["cap"] == nil {
		return nil
	}
	c, err := capFromJSON(i["cap"])
	if err == nil {
		err = c.validate()
	}
	if err != nil {
		panic(err)
	}
	return c
}

func (e *Engine) mint(claims map[string]any, event string, now int64) map[string]any {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		throw("crypto", "no randomness: "+err.Error())
	}
	jti := hex.EncodeToString(raw)
	claims["jti"] = jti
	token, serr := e.keys.sign(claims)
	if serr != nil {
		panic(serr)
	}
	capJSON := claims["cap"].(map[string]any)
	if budget := capJSON["budget"].(map[string]any); len(budget) > 0 {
		limit := make(map[string]any, len(budget))
		for k, v := range budget {
			limit[k] = v
		}
		e.state.section("limits")[jti] = limit
		e.state.prune(now)
		e.state.save()
	}
	user, chain := userOf(claims), strList(chainOf(claims))
	exp := claims["exp"].(int64)
	e.record(map[string]any{"event": event, "token_id": jti, "user": user, "chain": chain, "tenant": claims["tnt"],
		"task": claims["task"], "role": claims["role"], "ancestors": claims["anc"], "exp": exp, "cap": capJSON,
		"policy_version": e.bundle.Version}, now)
	return map[string]any{"token": token, "token_type": "Bearer", "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"token_id": jti, "expires_at": exp, "expires_in": satSub(exp, now),
		"user": user, "chain": chain, "role": claims["role"], "task": claims["task"], "cap": capJSON}
}

func (e *Engine) ttl(i map[string]any) int64 {
	t := integer(i, "ttl", e.defaultTTL)
	if t > e.maxTTL {
		t = e.maxTTL
	}
	if t < 1 {
		t = 1
	}
	return t
}

func (e *Engine) issueToken(i map[string]any) map[string]any {
	now := e.now(i)
	var user string
	var groups []any
	hasGroups := false
	if idt, ok := str(i, "id_token"); ok {
		if e.idp == nil {
			throw("no_idp", "no OIDC provider is configured")
		}
		claims, err := verifyIDToken(idt, e.idp.jwks.(map[string]any), e.idp.issuer, e.idp.audience, now)
		if err != nil {
			panic(err)
		}
		user, ok = claims[e.idp.userClaim].(string)
		if !ok || user == "" {
			throw("id_token_invalid", "ID token has no '"+e.idp.userClaim+"' claim")
		}
		if u, ok := str(i, "user"); ok && u != user {
			throw("id_token_invalid", "the ID token belongs to a different user")
		}
		// Offboarding also covers sign-ins that happened before it: an ID
		// token issued at or before the user's revoke cut-off cannot start a
		// new agent, however long the provider says it lives.
		stale := false
		switch cutoff := e.state.section("revoked_users")[user].(type) {
		case int64:
			iat, isInt := claims["iat"].(int64)
			_, isBig := claims["iat"].(*big.Int)
			stale = !(isInt && iat > cutoff) && !(isBig && claims["iat"].(*big.Int).Sign() > 0)
		case *big.Int:
			stale = true
		}
		if stale {
			throw("id_token_invalid", "the ID token was issued before this user was revoked; sign in again")
		}
		if e.idp.groupsClaim != "" {
			// the identity provider is the authority on what this human is a
			// member of right now; a missing claim means "of nothing". A
			// dotted name reads a nested claim (Keycloak: realm_access.roles).
			raw := claims[e.idp.groupsClaim]
			if raw == nil && strings.Contains(e.idp.groupsClaim, ".") {
				raw, _ = lookup(claims, e.idp.groupsClaim)
			}
			if raw == nil {
				raw = []any{}
			}
			if groups, err = e.groups(raw, e.idp.groupType, e.idp.groupMap); err != nil {
				throw("id_token_invalid", "the '"+e.idp.groupsClaim+"' claim is not a list of group names")
			}
			hasGroups = true
		}
	} else {
		user = req(i, "user")
		if i["groups"] != nil {
			var err *EngineError
			if groups, err = e.groups(i["groups"], "Group", nil); err != nil {
				panic(err)
			}
			hasGroups = true
		}
	}
	agent := req(i, "agent")
	c := parseCap(i)
	role, hasRole := str(i, "role")
	if !hasRole && e.requireRole {
		throw("role_required", "this engine issues tokens only for a named role")
	}
	if c == nil && !hasRole {
		throw("invalid_cap", "'cap' is required: a root token must state what it may do")
	}
	ttl := e.ttl(i)
	p := &principal{user: user, chain: []string{agent}, tenant: strOrNil(i, "tenant"), task: strOrNil(i, "task"), cap: c,
		exp: satAdd(now, ttl), role: strOrNil(i, "role"), groups: groups, hasGroups: hasGroups}
	if hasRole {
		c, ttl = e.applyRole(role, p, c, ttl)
		p.cap, p.exp = c, satAdd(now, ttl)
	}
	e.checkDelegation(entity("User", user), agent, p, c, ttl)
	claims := map[string]any{"iss": e.issuer, "aud": audience, "sub": "user:" + user, "iat": now, "exp": satAdd(now, ttl), "jti": "",
		"act": actFor(p.chain), "anc": []any{}, "cap": c.toJSON()}
	if p.tenant != nil {
		claims["tnt"] = p.tenant
	}
	if p.task != nil {
		claims["task"] = p.task
	}
	if hasRole {
		claims["role"] = role
	}
	if hasGroups {
		claims["grp"] = groups
	}
	return e.mint(claims, "token_issued", now)
}

// denyAsError turns a *deny panic into the engine error of the same code.
func denyAsError() {
	if r := recover(); r != nil {
		if d, ok := r.(*deny); ok {
			panic(newErr(d.code, d.detail))
		}
		panic(r)
	}
}

func (e *Engine) exchangeToken(i map[string]any) map[string]any {
	now := e.now(i)
	subject := req(i, "subject_token")
	var parent map[string]any
	func() {
		defer denyAsError()
		parent = e.verifyToken(subject, now)
	}()
	pp := principalOf(parent)
	actor := req(i, "actor")
	if int64(len(pp.chain)) >= e.maxDepth {
		throw("depth_exceeded", fmt.Sprintf("delegation chains are limited to %d agents", e.maxDepth))
	}
	c := parseCap(i)
	if c == nil {
		c = pp.cap
	}
	if err := c.checkNarrowerThan(pp.cap); err != nil {
		panic(err)
	}
	exp := satAdd(now, e.ttl(i))
	if parentExp := parent["exp"].(int64); parentExp < exp {
		exp = parentExp
	}
	if task, ok := str(i, "task"); ok && truthy(pp.task) && !pyEqual(task, pp.task) {
		throw("widening", "a sub-agent token cannot change the task it was issued for")
	}
	if role, ok := str(i, "role"); ok && !pyEqual(role, pp.role) {
		throw("widening", "a sub-agent token cannot change the role it was issued for")
	}
	e.checkDelegation(entity("Agent", pp.leaf()), actor, pp, c, satSub(exp, now))
	chain := append(append([]string{}, pp.chain...), actor)
	claims := map[string]any{"iss": e.issuer, "aud": audience, "sub": parent["sub"], "iat": now, "exp": exp, "jti": "",
		"act": actFor(chain), "anc": append(append([]any{}, parent["anc"].([]any)...), parent["jti"]), "cap": c.toJSON()}
	if truthy(parent["tnt"]) {
		claims["tnt"] = parent["tnt"]
	}
	task := pp.task
	if !truthy(task) {
		task = strOrNil(i, "task")
	}
	if truthy(task) {
		claims["task"] = task
	}
	if pp.role != nil {
		claims["role"] = pp.role
	}
	if pp.hasGroups {
		claims["grp"] = pp.groups
	}
	// every ancestor's budget travels with the token (see the budget check)
	lim := map[string]any{}
	for k, v := range pp.lim {
		lim[k] = v
	}
	if len(pp.cap.Budget) > 0 {
		lim[parent["jti"].(string)] = pp.cap.budgetJSON()
	}
	if len(lim) > 0 {
		claims["lim"] = lim
	}
	return e.mint(claims, "token_exchanged", now)
}

func (e *Engine) inspectToken(i map[string]any) (out map[string]any) {
	now := e.now(i)
	token := req(i, "token")
	defer func() {
		if r := recover(); r != nil {
			d, ok := r.(*deny)
			if !ok {
				panic(r)
			}
			out = map[string]any{"valid": false, "reason": d.code, "detail": d.detail}
		}
	}()
	c := e.verifyToken(token, now)
	return map[string]any{"valid": true, "claims": c, "chain": strList(chainOf(c)), "user": userOf(c), "expires_in": satSub(c["exp"].(int64), now)}
}

func (e *Engine) revoke(i map[string]any) map[string]any {
	now := e.now(i)
	if raw, has := i["user"]; has {
		// Offboarding, or a human who lost a role: one call ends every token
		// already issued for them, sub-agents included. New tokens are a
		// matter of role membership, not of this list.
		user, ok := raw.(string)
		if !ok || user == "" {
			throw("invalid_input", "'user' must be a non-empty string")
		}
		// the cut-off only ever moves forward: a clock that steps back (or a
		// second machine with a slower clock) must not revive dead tokens
		var cutoff any = now
		switch prev := e.state.section("revoked_users")[user].(type) {
		case int64:
			if prev > now {
				cutoff = prev
			}
		case *big.Int:
			if prev.Sign() > 0 {
				cutoff = prev
			}
		}
		e.state.section("revoked_users")[user] = cutoff
		e.state.save()
		e.record(map[string]any{"event": "user_revoked", "user": user, "issued_up_to": cutoff, "by": strOrNil(i, "by")}, now)
		return map[string]any{"revoked_user": user, "issued_up_to": cutoff}
	}
	var tid string
	var exp int64
	if t, ok := str(i, "token"); ok {
		c, err := e.keys.verify(t, e.issuer)
		if err != nil {
			throw("token_invalid", err.Error())
		}
		tid, exp = c["jti"].(string), c["exp"].(int64)
	} else {
		tid, exp = req(i, "token_id"), satAdd(now, e.maxTTL)
	}
	e.state.section("revoked")[tid] = exp
	e.state.save()
	e.record(map[string]any{"event": "token_revoked", "token_id": tid, "by": strOrNil(i, "by")}, now)
	return map[string]any{"revoked": tid}
}

func (e *Engine) approve(i map[string]any) map[string]any {
	now := e.now(i)
	aid, by := req(i, "approval_id"), req(i, "by")
	raw, has := e.state.section("pending")[aid]
	if !has || raw == nil {
		throw("unknown_approval", "no pending request with that approval id")
	}
	pending := raw.(map[string]any)
	if pyEqual(pending["user"], by) {
		throw("self_approval", "the user an agent acts for cannot approve that agent's request")
	}
	// who may approve is itself policy: action "approve" on the agent
	ctx, err := fromJSON(map[string]any{"label": pending["label"], "for_user": pending["user"], "action": pending["action"]})
	if err != nil {
		panic(err)
	}
	v := e.evaluate(entity("User", by), "approve", entity("Agent", pending["agent"].(string)), ctx.(map[string]any), e.bundle.store)
	if !v.allow {
		throw("approval_denied", "no policy lets '"+by+"' approve this request")
	}
	delete(e.state.section("pending"), aid)
	exp := satAdd(now, integer(i, "ttl", e.approvalTTL))
	e.state.section("approvals")[aid] = map[string]any{"by": by, "exp": exp}
	e.state.save()
	e.record(map[string]any{"event": "approval_granted", "approval_id": aid, "by": by, "label": pending["label"],
		"for_user": pending["user"], "agent": pending["agent"], "action": pending["action"],
		"resource": pending["resource"]}, now)
	return map[string]any{"approved": aid, "by": by, "expires_at": exp}
}

// applyObligations applies the obligations of an earlier decision to data
// that arrived later. Pure: it authorises nothing by itself.
func (e *Engine) applyObligations(i map[string]any) map[string]any {
	ob, ok := i["obligations"].(map[string]any)
	if !ok {
		throw("invalid_input", "'obligations' from a decision is required")
	}
	data, has := i["data"]
	if !has {
		throw("invalid_input", "'data' is required")
	}
	f, ok := ob["fields"].(map[string]any)
	if !ok {
		throw("invalid_input", "obligations.fields is missing; only an allow decision carries a field mask")
	}
	status := map[string]string{}
	for _, kind := range []string{fieldAllow, fieldDeny, fieldRedact} {
		list, _ := f[kind].([]any)
		for _, x := range list {
			if s, ok := x.(string); ok {
				status[s] = kind
			}
		}
	}
	var rowFilter []map[string]any
	if rf, ok := ob["row_filter"].([]any); ok {
		for _, c := range rf {
			if cm, ok := c.(map[string]any); ok {
				rowFilter = append(rowFilter, cm)
			}
		}
	}
	out, masked, dropped := applyMask(data, &fieldMask{status}, rowFilter)
	if did, ok := str(i, "decision_id"); ok {
		e.record(map[string]any{"event": "obligations_applied", "decision_id": did, "masked": strList(masked), "rows_dropped": dropped}, e.now(i))
	}
	return map[string]any{"data": out, "masked": strList(masked), "rows_dropped": dropped}
}

// ---- decisions -------------------------------------------------------------------------

func (e *Engine) evaluateRequest(i map[string]any, now int64, dryRun bool) *outcome {
	o := &outcome{policies: []string{}}
	func() {
		defer func() {
			if r := recover(); r != nil {
				d, ok := r.(*deny)
				if !ok {
					panic(r)
				}
				o.reason, o.detail = d.code, d.detail
				o.trace = append(o.trace, map[string]any{"check": d.code, "result": "deny", "detail": d.detail})
			}
		}()
		e.steps(o, i, now, dryRun)
	}()
	return o
}

func (e *Engine) steps(o *outcome, i map[string]any, now int64, dryRun bool) {
	passed := func(check, msg string) {
		o.trace = append(o.trace, map[string]any{"check": check, "result": "pass", "detail": msg})
	}

	action := req(i, "action")
	res, ok := i["resource"].(map[string]any)
	if !ok {
		throw("invalid_input", "'resource' must be an object with a 'path'")
	}
	path := req(res, "path")
	rid := "any"
	if s, ok := str(res, "id"); ok {
		rid = s
	}
	callerCtx := map[string]any{}
	if raw := i["context"]; raw != nil {
		if callerCtx, ok = raw.(map[string]any); !ok {
			throw("invalid_context", "'context' must be an object")
		}
	}
	if _, has := callerCtx["iam"]; has {
		throw("invalid_context", "'iam' is reserved: identity comes from the token, not from the caller")
	}

	// 1. principal
	var p *principal
	token, hasToken := str(i, "token")
	chain := i["chain"]
	chainMap, chainIsMap := chain.(map[string]any)
	switch {
	case hasToken:
		func() {
			defer func() {
				if r := recover(); r != nil {
					if d, ok := r.(*deny); ok && len(d.claims) > 0 {
						o.principal = principalOf(d.claims)
					}
					panic(r)
				}
			}()
			p = principalOf(e.verifyToken(token, now))
		}()
	case chain != nil && e.trustChain && chainIsMap:
		var agents []string
		if list, ok := chainMap["agents"].([]any); ok {
			for _, a := range list {
				if s, ok := a.(string); ok {
					agents = append(agents, s)
				}
			}
		}
		if len(agents) == 0 {
			throw("invalid_input", "chain.agents must list at least one agent")
		}
		p = &principal{user: req(chainMap, "user"), chain: agents, tenant: strOrNil(chainMap, "tenant"), task: strOrNil(chainMap, "task"),
			cap: unrestrictedCap(), exp: now, role: strOrNil(chainMap, "role")}
		if chainMap["groups"] != nil {
			g, err := e.groups(chainMap["groups"], "Group", nil)
			if err != nil {
				panic(err)
			}
			p.groups, p.hasGroups = g, true
		}
	case chain != nil:
		panic(&deny{code: "token_invalid", detail: "this engine does not trust caller-supplied chains; send a capability token"})
	default:
		panic(&deny{code: "token_invalid", detail: "no capability token was presented"})
	}
	o.principal = p
	passed("token", "user "+p.user+" via "+strings.Join(p.chain, " -> "))

	// 2. catalog
	rdef := e.bundle.catalog[path]
	if rdef == nil {
		panic(&deny{code: "unknown_resource", detail: "'" + path + "' is not in the catalog"})
	}

	// 3. tenant
	attrs := map[string]any{}
	if raw := res["attrs"]; raw != nil {
		if attrs, ok = raw.(map[string]any); !ok {
			throw("invalid_input", "resource.attrs must be an object")
		}
	}
	if rt, ok := attrs["tenant"].(string); ok && truthy(p.tenant) && !pyEqual(p.tenant, rt) {
		panic(&deny{code: "tenant_mismatch", detail: fmt.Sprintf("token tenant '%v' cannot touch a resource of tenant '%s'", p.tenant, rt)})
	}

	// 4. capability
	if !p.cap.allowsAction(action) {
		panic(&deny{code: "capability_action", detail: "the token does not carry action '" + action + "'"})
	}
	if !p.cap.allowsResource(path, rid) {
		panic(&deny{code: "capability_resource", detail: "the token does not cover " + path + "/" + rid})
	}
	passed("capability", "token covers the action and the resource")

	// 5. policy
	etype := rdef.entityType
	rUID := entity(etype, rid)
	var fieldNames []string
	if list, ok := i["fields"].([]any); ok {
		for _, f := range list {
			name, isStr := f.(string)
			if _, known := rdef.fields[name]; !isStr || !known {
				shown := name
				if !isStr {
					shown = Canon(f)
				}
				panic(&deny{code: "unknown_field", detail: "'" + path + "." + shown + "' is not in the catalog"})
			}
			fieldNames = append(fieldNames, name)
		}
	} else {
		fieldNames = sortedKeys(rdef.fields)
	}
	var extra []any
	if !e.bundle.store.has(rUID) {
		extra = append(extra, map[string]any{"uid": map[string]any{"type": etype, "id": rid}, "attrs": attrs, "parents": []any{}})
	} else if len(attrs) > 0 {
		throw("invalid_input", rUID.String()+" is defined in entities.json; do not send attrs for it")
	}
	for _, n := range fieldNames {
		fid := path + "." + n
		extra = append(extra, map[string]any{"uid": map[string]any{"type": "Field", "id": fid},
			"attrs": map[string]any{"path": fid, "name": n, "resource": path, "labels": rdef.fields[n].labels,
				"of": map[string]any{"__entity": map[string]any{"type": etype, "id": rid}}},
			"parents": []any{map[string]any{"type": etype, "id": rid}}})
	}
	store, serr := e.storeFor(p).overlay(extra)
	if serr != nil {
		throw("invalid_input", "resource entity: "+serr.Error())
	}
	fullCtx := make(map[string]any, len(callerCtx)+1)
	for k, v := range callerCtx {
		fullCtx[k] = v
	}
	fullCtx["iam"] = e.iamContext(p)
	ctxAny, cerr := fromJSON(fullCtx)
	if cerr != nil {
		throw("invalid_context", cerr.Error()+" (use integers, strings, booleans, lists and objects; no floats or nulls)")
	}
	ctx := ctxAny.(map[string]any)
	pUID := entity("Agent", p.leaf())
	v := e.evaluate(pUID, action, rUID, ctx, store)
	o.errors = append(o.errors, v.errors...)
	o.policies = append([]string{}, v.policies...)
	if !v.allow {
		if v.forbidError {
			panic(&deny{code: "policy_error", detail: "a forbid policy failed to evaluate, so the request is denied"})
		}
		if len(v.policies) == 0 {
			panic(&deny{code: "no_matching_permit", detail: "no policy permits this request"})
		}
		panic(&deny{code: "policy_forbid", detail: "forbidden by " + strings.Join(v.policies, ", ")})
	}
	passed("policy", "permitted by "+strings.Join(v.policies, ", "))

	// 6. obligations carried by the permits that decided
	var approvalLabel any
	needsApproval := false
	for _, pid := range v.policies {
		ann := e.bundle.Policies[pid].Annotations
		if rf, has := ann["row_filter"]; has {
			func() {
				defer func() {
					if r := recover(); r != nil {
						if d, ok := r.(*deny); ok {
							panic(&deny{code: d.code, detail: pid + ": " + d.detail})
						}
						panic(r)
					}
				}()
				o.rowFilter = append(o.rowFilter, parseRowFilter(rf.(string), fullCtx)...)
			}()
		}
		if rl, has := ann["rate_limit"]; has {
			text := ""
			if truthy(rl) {
				text = rl.(string)
			}
			n, w, ok := parseRate(text)
			if !ok {
				panic(&deny{code: "policy_error", detail: pid + `: rate_limit must be "<count>/<seconds>"`})
			}
			o.rate = append(o.rate, rateRule{pid + "|" + p.leaf() + "|" + p.user, n, w})
		}
		if label, has := ann["require_approval"]; has {
			approvalLabel, needsApproval = label, true
		}
	}
	for _, r := range o.rate {
		q := e.rate[r.key]
		for len(q) > 0 && q[0] <= satSub(now, clamp(r.window)) {
			q = q[1:]
		}
		e.rate[r.key] = q
		o.rateLimit = map[string]any{"limit": r.limit, "window_seconds": r.window, "used": int64(len(q))}
		if n, fits := r.limit.(int64); fits && int64(len(q)) >= n {
			panic(&deny{code: "rate_limited", detail: fmt.Sprintf("more than %d calls in %v seconds", n, r.window)})
		}
	}

	// 7. budget
	if sp, has := callerCtx["spend"]; has {
		spm, _ := sp.(map[string]any)
		cur, okCur := spm["currency"].(string)
		amount, okAmount := spm["amount"].(int64)
		if !okCur || !okAmount || amount < 0 {
			throw("invalid_context", "context.spend must be {currency: string, amount: non-negative integer in minor units}")
		}
		if !p.hasJTI {
			panic(&deny{code: "budget_exceeded", detail: "spending needs a capability token with a budget"})
		}
		own, has := p.cap.Budget[cur]
		if !has {
			panic(&deny{code: "budget_exceeded", detail: "the token carries no " + cur + " budget"})
		}
		ledger, limits := e.state.section("ledger"), e.state.section("limits")
		spent := func(tid string) int64 {
			bucket, _ := ledger[tid]
			if bucket == nil {
				return 0
			}
			if v, has := bucket.(map[string]any)[cur]; has {
				return num(v)
			}
			return 0
		}
		over := func(spent, limit int64) bool { // spent + amount > limit, without overflow
			sum := new(big.Int).Add(big.NewInt(spent), big.NewInt(amount))
			return sum.Cmp(big.NewInt(limit)) > 0
		}
		if over(spent(p.jti), own) {
			panic(&deny{code: "budget_exceeded", detail: fmt.Sprintf("%d %s would exceed this token's budget of %d (already spent %d)", amount, cur, own, spent(p.jti))})
		}
		for _, a := range p.anc {
			// An ancestor's budget is in this engine's state when it issued
			// the ancestor, and in the token's `lim` claim always: a
			// verify-only engine elsewhere must enforce it too.
			var limit any
			if entry, has := limits[a]; has {
				limit = entry.(map[string]any)[cur]
			}
			if limit == nil {
				if entry, has := p.lim[a].(map[string]any); has {
					limit = entry[cur]
				}
			}
			if _, huge := limit.(*big.Int); huge {
				continue // a limit beyond 64 bits cannot be reached by 64-bit spends
			}
			if limit != nil && over(spent(a), num(limit)) {
				panic(&deny{code: "budget_exceeded", detail: fmt.Sprintf("%d %s would exceed the budget of ancestor token %s", amount, cur, a)})
			}
		}
		o.spend, o.spendCur, o.spendAmount = true, cur, amount
		passed("budget", "within the budget of every token in the chain")
	}

	// 8. human approval
	if needsApproval {
		target := path + "/" + rid
		aid := hashValue(map[string]any{"user": p.user, "chain": strList(p.chain), "tenant": p.tenant, "action": action,
			"resource": target, "attrs": attrs, "context": callerCtx, "label": approvalLabel})[:24]
		if grant, _ := e.state.section("approvals")[aid].(map[string]any); len(grant) > 0 && num(grant["exp"]) > now {
			by, has := grant["by"]
			if !has {
				panic("an approval in state.json has no approver")
			}
			o.approved, o.approvedID, o.approvedBy = true, aid, by
			passed("approval", fmt.Sprintf("approved by %v", by))
		} else {
			if !dryRun {
				e.state.section("pending")[aid] = map[string]any{"label": approvalLabel, "user": p.user, "agent": p.leaf(),
					"action": action, "resource": target, "requested_at": now}
				e.state.save()
			}
			o.approval = map[string]any{"id": aid, "label": approvalLabel}
			panic(&deny{code: "approval_required", detail: fmt.Sprintf("a human must approve this (%v)", approvalLabel)})
		}
	}

	// 9. fields
	status := map[string]string{}
	fieldTrace := []any{}
	for _, n := range fieldNames {
		fid := path + "." + n
		fdef := rdef.fields[n]
		allowed := false
		var by any = "capability"
		byCap := contains(p.cap.DenyFields, fid)
		for _, l := range fdef.labels {
			if s, ok := l.(string); ok && contains(p.cap.DenyLabels, s) {
				byCap = true
			}
		}
		if !byCap {
			fv := e.evaluate(pUID, action, Entity{"Field", fid}, ctx, store)
			o.errors = append(o.errors, fv.errors...)
			allowed = fv.allow
			if len(fv.policies) > 0 {
				by = strList(fv.policies)
			} else {
				by = "no_matching_permit"
			}
		}
		effect := "deny"
		if allowed {
			effect = "allow"
			o.fieldAllow = append(o.fieldAllow, n)
			status[n] = fieldAllow
		} else {
			o.fieldDeny = append(o.fieldDeny, n)
			if fdef.mask == "redact" {
				o.fieldRedact = append(o.fieldRedact, n)
				status[n] = fieldRedact
			} else {
				status[n] = fieldDeny
			}
		}
		fieldTrace = append(fieldTrace, map[string]any{"field": n, "effect": effect, "by": by})
	}
	o.trace = append(o.trace, map[string]any{"check": "fields", "result": "pass", "fields": fieldTrace})
	o.mask = &fieldMask{status}
	o.allow = true
	o.reason = "policy_permit"
}

func (e *Engine) decide(i map[string]any, withData bool) map[string]any {
	now := e.now(i)
	dryRun := i["dry_run"] == true
	strict := i["strict"] == true
	data, hasData := i["data"]
	if withData && !hasData {
		throw("invalid_input", "'data' is required for filter")
	}
	o := e.evaluateRequest(i, now, dryRun)

	// 10. strict mode: for tool *inputs*, where silently dropping a field
	// would change what the agent asked for
	if o.allow && strict && withData {
		if _, denied, _ := applyMask(data, o.mask, nil); len(denied) > 0 {
			o.allow = false
			o.reason = "field_denied"
			o.detail = "the input contains fields this principal may not use: " + strings.Join(denied, ", ")
			o.trace = append(o.trace, map[string]any{"check": "field_denied", "result": "deny", "detail": o.detail})
		}
	}

	// commit the side effects of an allowed call
	if o.allow && !dryRun {
		for _, r := range o.rate {
			e.rate[r.key] = append(e.rate[r.key], now)
		}
		dirty := false
		if o.spend && o.principal != nil {
			ledger := e.state.section("ledger")
			var ids []any
			for _, a := range o.principal.anc {
				ids = append(ids, a)
			}
			ids = append(ids, o.principal.tokenID())
			for _, tid := range ids {
				bucket, _ := ledger[tid.(string)].(map[string]any)
				if bucket == nil {
					if _, has := ledger[tid.(string)]; has {
						panic("the spend ledger in state.json is malformed")
					}
					bucket = map[string]any{}
					ledger[tid.(string)] = bucket
				}
				var spent int64
				if v, has := bucket[o.spendCur]; has {
					spent = num(v)
				}
				sum, err := addChecked(spent, o.spendAmount)
				if err != nil {
					panic("the spend ledger would overflow a 64-bit integer")
				}
				bucket[o.spendCur] = sum
			}
			dirty = true
		}
		if o.approved {
			// an approval is good for one call
			delete(e.state.section("approvals"), o.approvedID)
			dirty = true
		}
		if dirty {
			e.state.save()
		}
	}

	wouldDeny := !o.allow
	shadowed := e.shadow && wouldDeny
	out := map[string]any{"effect": "deny", "reason": o.reason}
	if o.allow || shadowed {
		out["effect"] = "allow"
	}
	if shadowed {
		out["reason"] = "shadow_allow"
	}
	out["rule"] = RuleID(out["reason"].(string))
	if o.detail != "" && !shadowed {
		out["detail"] = o.detail
	}
	out["policies"] = strList(o.policies)
	out["policy_version"] = e.bundle.Version
	out["principal"] = nil
	if o.principal != nil {
		out["principal"] = o.principal.toJSON()
	}
	if e.shadow {
		out["shadow"] = true
		if wouldDeny {
			out["would_deny"] = map[string]any{"reason": o.reason, "detail": o.detail}
		}
	}
	if o.approval != nil {
		out["approval"] = o.approval
	}

	obligations := map[string]any{}
	masked := []string{}
	var rowsDropped int64
	if o.allow {
		obligations["fields"] = map[string]any{"allow": strList(o.fieldAllow), "deny": strList(o.fieldDeny), "redact": strList(o.fieldRedact)}
		if len(o.rowFilter) > 0 {
			rf := make([]any, len(o.rowFilter))
			for k, c := range o.rowFilter {
				rf[k] = c
			}
			obligations["row_filter"] = rf
		}
		if o.rateLimit != nil {
			obligations["rate_limit"] = o.rateLimit
		}
		if o.approved {
			obligations["approved"] = map[string]any{"id": o.approvedID, "by": o.approvedBy}
		}
	}
	if withData {
		if o.allow {
			var filtered any
			filtered, masked, rowsDropped = applyMask(data, o.mask, o.rowFilter)
			if e.shadow {
				// shadow mode never changes data; it reports what it would do
				out["data"], out["would_mask"], out["would_drop_rows"] = data, strList(masked), rowsDropped
			} else {
				out["data"], out["masked"], out["rows_dropped"] = filtered, strList(masked), rowsDropped
			}
		} else if shadowed {
			out["data"] = data
		} else {
			out["data"] = nil
		}
	}
	out["obligations"] = obligations
	if len(o.errors) > 0 {
		out["policy_errors"] = o.errors
	}
	if i["explain"] == true {
		trace := o.trace
		if trace == nil {
			trace = []any{}
		}
		out["explain"] = trace
	}

	e.counter++
	var tokenID any
	if o.principal != nil {
		tokenID = o.principal.tokenID()
	}
	requestHash := hashValue(map[string]any{"action": i["action"], "resource": i["resource"], "context": i["context"], "token_id": tokenID})
	decisionID := "d-" + sha256Hex([]byte(requestHash + strconv.FormatInt(now, 10) + strconv.FormatUint(e.counter, 10) + e.pidLabel))[:16]
	out["decision_id"] = decisionID

	if !dryRun {
		op := "authorize"
		if withData {
			op = "filter"
		}
		effect := "deny"
		if o.allow {
			effect = "allow"
		}
		rec := map[string]any{
			"event": "decision", "decision_id": decisionID, "op": op,
			"effect": effect, "reason": o.reason, "detail": o.detail,
			"enforced": !e.shadow, "policies": strList(o.policies), "policy_version": e.bundle.Version,
			"user": nil, "chain": nil, "role": nil, "tenant": nil, "task": nil, "token_id": nil, "token_exp": nil,
			"action":      i["action"],
			"obligations": obligations, "masked": strList(masked), "rows_dropped": rowsDropped, "approval": nil,
			"spend": nil, "request_hash": requestHash,
		}
		if p := o.principal; p != nil {
			rec["user"], rec["chain"], rec["role"], rec["tenant"] = p.user, strList(p.chain), p.role, p.tenant
			rec["task"], rec["token_id"], rec["token_exp"] = p.task, p.tokenID(), p.exp
		}
		resPath, resID := "?", "any"
		if s, ok := str(i["resource"], "path"); ok {
			resPath = s
		}
		if s, ok := str(i["resource"], "id"); ok {
			resID = s
		}
		rec["resource"] = resPath + "/" + resID
		if o.approval != nil {
			rec["approval"] = o.approval
		}
		if o.spend {
			rec["spend"] = map[string]any{"currency": o.spendCur, "amount": o.spendAmount}
		}
		e.record(rec, now)
	}
	return out
}
