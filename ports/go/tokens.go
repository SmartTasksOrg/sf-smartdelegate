package smartdelegate

// Capability tokens: EdDSA-signed JWTs with an RFC 8693 `act` delegation
// chain and a `cap` claim that can only be narrowed on each hop. Also the
// verification of OIDC ID tokens against a static JWKS.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

const audience = "smartdelegate"

func b64u(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// b64uDec decodes base64url strictly: only A-Z a-z 0-9 - _, no padding,
// nothing skipped. One token has one spelling.
func b64uDec(text string) ([]byte, error) {
	if text == "" || len(text)%4 == 1 {
		return nil, errors.New("not base64url")
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, errors.New("not base64url")
		}
	}
	return base64.RawURLEncoding.DecodeString(text)
}

// b64Strict decodes standard base64 with padding; nothing else is accepted.
func b64Strict(text string) ([]byte, error) {
	if strings.ContainsAny(text, "\r\n") {
		return nil, errors.New("not base64")
	}
	return base64.StdEncoding.DecodeString(text)
}

// ---- capability ----------------------------------------------------------------

// Cap is a capability: actions and resources are names with an optional
// single trailing `*` (resources are `<path>/<id>`); DenyLabels and
// DenyFields are what the token can never see, whatever policy says; Budget
// maps a currency to the total spend in minor units.
type Cap struct {
	Actions    []string
	Resources  []string
	DenyLabels []string
	DenyFields []string
	Budget     map[string]int64
}

func capStrList(v any, what string) ([]string, *EngineError) {
	if v == nil {
		return []string{}, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, newErr("invalid_cap", what+" must be a list of strings")
	}
	out := make([]string, len(list))
	for i, x := range list {
		s, ok := x.(string)
		if !ok {
			return nil, newErr("invalid_cap", what+" must be a list of strings")
		}
		out[i] = s
	}
	return out, nil
}

// capFromJSON reads a `cap` object. Unknown fields are an error: a misspelt
// key must not silently become "no restriction".
func capFromJSON(v any) (*Cap, *EngineError) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, newErr("invalid_cap", "cap must be an object")
	}
	var unknown []string
	for k := range m {
		switch k {
		case "actions", "resources", "deny_labels", "deny_fields", "budget":
		default:
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, newErr("invalid_cap", "unknown cap field(s): "+strings.Join(unknown, ", "))
	}
	c := &Cap{Budget: map[string]int64{}}
	var err *EngineError
	if c.Actions, err = capStrList(m["actions"], "cap.actions"); err != nil {
		return nil, err
	}
	if c.Resources, err = capStrList(m["resources"], "cap.resources"); err != nil {
		return nil, err
	}
	if c.DenyLabels, err = capStrList(m["deny_labels"], "cap.deny_labels"); err != nil {
		return nil, err
	}
	if c.DenyFields, err = capStrList(m["deny_fields"], "cap.deny_fields"); err != nil {
		return nil, err
	}
	if b := m["budget"]; truthy(b) {
		bm, ok := b.(map[string]any)
		if !ok {
			return nil, newErr("invalid_cap", "cap.budget must map currency to an integer amount in minor units")
		}
		for cur, amount := range bm {
			n, ok := amount.(int64)
			if !ok {
				return nil, newErr("invalid_cap", "cap.budget must map currency to an integer amount in minor units")
			}
			c.Budget[cur] = n
		}
	}
	return c, nil
}

func unrestrictedCap() *Cap {
	return &Cap{Actions: []string{"*"}, Resources: []string{"*"}, DenyLabels: []string{}, DenyFields: []string{}, Budget: map[string]int64{}}
}

func (c *Cap) clone() *Cap {
	out := &Cap{Actions: append([]string{}, c.Actions...), Resources: append([]string{}, c.Resources...),
		DenyLabels: append([]string{}, c.DenyLabels...), DenyFields: append([]string{}, c.DenyFields...), Budget: map[string]int64{}}
	for k, v := range c.Budget {
		out.Budget[k] = v
	}
	return out
}

func (c *Cap) budgetJSON() map[string]any {
	out := make(map[string]any, len(c.Budget))
	for k, v := range c.Budget {
		out[k] = v
	}
	return out
}

func (c *Cap) toJSON() map[string]any {
	return map[string]any{"actions": strList(c.Actions), "resources": strList(c.Resources), "deny_labels": strList(c.DenyLabels),
		"deny_fields": strList(c.DenyFields), "budget": c.budgetJSON()}
}

func (c *Cap) validate() *EngineError {
	for _, list := range [][]string{c.Actions, c.Resources} {
		for _, p := range list {
			if p == "" || strings.Contains(p[:len(p)-1], "*") {
				return newErr("invalid_cap", "pattern '"+p+"': only one trailing * is allowed")
			}
		}
	}
	for _, v := range c.Budget {
		if v < 0 {
			return newErr("invalid_cap", "budget cannot be negative")
		}
	}
	return nil
}

func (c *Cap) allowsAction(action string) bool {
	for _, p := range c.Actions {
		if patternMatches(p, action) {
			return true
		}
	}
	return false
}

func (c *Cap) allowsResource(path, id string) bool {
	s := path + "/" + id
	for _, p := range c.Resources {
		if patternMatches(p, s) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// checkNarrowerThan fails with `widening` unless c grants nothing the parent does not.
func (c *Cap) checkNarrowerThan(parent *Cap) *EngineError {
	covered := func(patterns []string, s string) bool {
		for _, p := range patterns {
			if patternCovers(p, s) {
				return true
			}
		}
		return false
	}
	for _, a := range c.Actions {
		if !covered(parent.Actions, a) {
			return newErr("widening", "action '"+a+"' is not covered by the parent token")
		}
	}
	for _, r := range c.Resources {
		if !covered(parent.Resources, r) {
			return newErr("widening", "resource '"+r+"' is not covered by the parent token")
		}
	}
	for _, l := range parent.DenyLabels {
		if !contains(c.DenyLabels, l) {
			return newErr("widening", "label '"+l+"' is denied by the parent and must stay denied")
		}
	}
	for _, f := range parent.DenyFields {
		if !contains(c.DenyFields, f) {
			return newErr("widening", "field '"+f+"' is denied by the parent and must stay denied")
		}
	}
	for _, cur := range sortedKeys(c.Budget) {
		limit, ok := parent.Budget[cur]
		if !ok {
			return newErr("widening", "the parent token has no "+cur+" budget to pass on")
		}
		if c.Budget[cur] > limit {
			return newErr("widening", fmt.Sprintf("budget %d %s exceeds the parent's %d", c.Budget[cur], cur, limit))
		}
	}
	return nil
}

func patternMatches(pattern, s string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return pattern == s
}

// patternCovers: does `parent` cover every string that `child` covers?
func patternCovers(parent, child string) bool {
	if strings.HasSuffix(parent, "*") {
		prefix := parent[:len(parent)-1]
		if strings.HasSuffix(child, "*") {
			return strings.HasPrefix(strings.TrimRight(child, "*"), prefix)
		}
		return strings.HasPrefix(child, prefix)
	}
	return !strings.HasSuffix(child, "*") && parent == child
}

// ---- claims ----------------------------------------------------------------------

// actFor builds the RFC 8693 actor chain: the current actor is outermost.
func actFor(chain []string) any {
	var act any
	for _, agent := range chain {
		if act == nil {
			act = map[string]any{"sub": "agent:" + agent}
		} else {
			act = map[string]any{"sub": "agent:" + agent, "act": act}
		}
	}
	return act
}

// chainOf lists the agents root-first: ["support-bot", "refund-helper"].
func chainOf(claims map[string]any) []string {
	out := []string{}
	cur, _ := claims["act"].(map[string]any)
	for cur != nil {
		sub, ok := cur["sub"].(string)
		if !ok {
			break
		}
		out = append(out, strings.TrimPrefix(sub, "agent:"))
		cur, _ = cur["act"].(map[string]any)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func userOf(claims map[string]any) string {
	sub, _ := claims["sub"].(string)
	return strings.TrimPrefix(sub, "user:")
}

// ---- keys ------------------------------------------------------------------------
// Private keys are base64 of the PKCS#8 DER encoding; public keys are base64
// of the 32 raw bytes. The key id is the first 16 hex characters of
// sha256(public).

type keyring struct {
	private   ed25519.PrivateKey
	kid       string
	publicB64 string
	verifiers map[string]ed25519.PublicKey
}

func newKeyring(privateB64 string, trusted []string) (*keyring, *EngineError) {
	k := &keyring{verifiers: map[string]ed25519.PublicKey{}}
	if privateB64 != "" {
		priv, err := loadPrivate(privateB64)
		if err != nil {
			return nil, err
		}
		pub := priv.Public().(ed25519.PublicKey)
		k.private = priv
		k.kid = sha256Hex(pub)[:16]
		k.publicB64 = base64.StdEncoding.EncodeToString(pub)
		k.verifiers[k.kid] = pub
	}
	for _, b := range trusted {
		pub, err := loadPublic(b)
		if err != nil {
			return nil, err
		}
		k.verifiers[sha256Hex(pub)[:16]] = pub
	}
	return k, nil
}

func (k *keyring) canSign() bool { return k.private != nil }

func (k *keyring) sign(claims map[string]any) (string, *EngineError) {
	if k.private == nil {
		return "", newErr("no_signing_key", "this engine can verify tokens but not issue them")
	}
	head := b64u([]byte(`{"typ":"JWT","alg":"EdDSA","kid":"` + k.kid + `"}`))
	body := b64u([]byte(Canon(claims)))
	return head + "." + body + "." + b64u(ed25519.Sign(k.private, []byte(head+"."+body))), nil
}

func isInt(v any) bool {
	switch v.(type) {
	case int64, *big.Int:
		return true
	}
	return false
}

// verify checks signature, shape, audience and issuer, in that order. Time
// and revocation belong to the engine, which owns the clock. The error text
// is the reason.
func (k *keyring) verify(token, issuer string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not a JWT")
	}
	headRaw, err1 := b64uDec(parts[0])
	sig, err2 := b64uDec(parts[2])
	if err1 != nil || err2 != nil {
		return nil, errors.New("token is not a JWT")
	}
	headAny, err := parseJSONBytes(headRaw)
	if err != nil {
		return nil, errors.New("token is not a JWT")
	}
	header, ok := headAny.(map[string]any)
	if alg, _ := header["alg"].(string); !ok || alg != "EdDSA" {
		return nil, errors.New("token algorithm is not EdDSA")
	}
	kid, ok := header["kid"].(string)
	if !ok {
		return nil, errors.New("token has no key id")
	}
	key, ok := k.verifiers[kid]
	if !ok {
		return nil, errors.New("token was signed by an unknown key")
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, errors.New("token rejected: bad signature")
	}
	claims, ok := parseClaims(parts[1])
	if !ok {
		return nil, errors.New("token rejected: malformed claims")
	}
	if claims["aud"] != audience {
		return nil, errors.New("token rejected: wrong audience")
	}
	if claims["iss"] != issuer {
		return nil, errors.New("token rejected: wrong issuer")
	}
	return claims, nil
}

func parseClaims(body string) (map[string]any, bool) {
	raw, err := b64uDec(body)
	if err != nil {
		return nil, false
	}
	v, err := parseJSONBytes(raw)
	if err != nil {
		return nil, false
	}
	claims, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	for _, k := range []string{"iss", "aud", "sub", "jti"} {
		if _, ok := claims[k].(string); !ok {
			return nil, false
		}
	}
	for _, k := range []string{"iat", "exp"} {
		// an integer outside 64 bits cannot be a time this engine can reason about
		if _, ok := claims[k].(int64); !ok {
			return nil, false
		}
	}
	if _, ok := claims["act"].(map[string]any); !ok {
		return nil, false
	}
	if anc, has := claims["anc"]; has {
		list, ok := anc.([]any)
		if !ok {
			return nil, false
		}
		for _, x := range list {
			if _, ok := x.(string); !ok {
				return nil, false
			}
		}
	} else {
		claims["anc"] = []any{}
	}
	if role, has := claims["role"]; has {
		if s, ok := role.(string); !ok || s == "" {
			return nil, false
		}
	}
	if grp, has := claims["grp"]; has {
		list, ok := grp.([]any)
		if !ok {
			return nil, false
		}
		for _, g := range list {
			gm, ok := g.(map[string]any)
			if !ok {
				return nil, false
			}
			_, okType := gm["type"].(string)
			_, okID := gm["id"].(string)
			if !okType || !okID {
				return nil, false
			}
		}
	}
	if raw, has := claims["lim"]; has {
		// ancestor token id -> {currency: non-negative integer}
		lim, ok := raw.(map[string]any)
		if !ok {
			return nil, false
		}
		for _, b := range lim {
			budget, ok := b.(map[string]any)
			if !ok {
				return nil, false
			}
			for _, v := range budget {
				switch n := v.(type) {
				case int64:
					if n < 0 {
						return nil, false
					}
				case *big.Int:
					if n.Sign() < 0 {
						return nil, false
					}
				default:
					return nil, false
				}
			}
		}
	}
	c, cerr := capFromJSON(claims["cap"])
	if cerr != nil {
		return nil, false
	}
	claims["cap"] = c.toJSON()
	return claims, true
}

// ---- OIDC ID tokens ----------------------------------------------------------------

func b64Int(v any) (*big.Int, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("key or signature is malformed")
	}
	raw, err := b64uDec(s)
	if err != nil {
		return nil, errors.New("key or signature is malformed")
	}
	return new(big.Int).SetBytes(raw), nil
}

var errBadSignature = errors.New("signature does not verify")

func verifyJWS(alg any, jwk map[string]any, signingInput, sig []byte) error {
	a, _ := alg.(string)
	kty, _ := jwk["kty"].(string)
	digest := func(bits string) (crypto.Hash, []byte) {
		switch bits {
		case "256":
			h := sha256.Sum256(signingInput)
			return crypto.SHA256, h[:]
		case "384":
			h := sha512.Sum384(signingInput)
			return crypto.SHA384, h[:]
		}
		h := sha512.Sum512(signingInput)
		return crypto.SHA512, h[:]
	}
	switch {
	case (a == "RS256" || a == "RS384" || a == "RS512") && kty == "RSA":
		e, err := b64Int(jwk["e"])
		if err != nil {
			return err
		}
		n, err := b64Int(jwk["n"])
		if err != nil {
			return err
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Bit(0) == 0 || n.Sign() <= 0 {
			return errors.New("key or signature is malformed")
		}
		hash, sum := digest(a[2:])
		if rsa.VerifyPKCS1v15(&rsa.PublicKey{N: n, E: int(e.Int64())}, hash, sum, sig) != nil {
			return errBadSignature
		}
		return nil
	case (a == "ES256" || a == "ES384") && kty == "EC":
		curve, size := elliptic.P256(), 32
		if a == "ES384" {
			curve, size = elliptic.P384(), 48
		}
		if len(sig) != 2*size {
			return errBadSignature
		}
		x, err := b64Int(jwk["x"])
		if err != nil {
			return err
		}
		y, err := b64Int(jwk["y"])
		if err != nil {
			return err
		}
		if !curve.IsOnCurve(x, y) {
			return errors.New("key or signature is malformed")
		}
		_, sum := digest(a[2:])
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, sum, r, s) {
			return errBadSignature
		}
		return nil
	case a == "EdDSA" && kty == "OKP" && jwk["crv"] == "Ed25519":
		xs, ok := jwk["x"].(string)
		if !ok {
			return errors.New("key or signature is malformed")
		}
		pub, err := b64uDec(xs)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return errors.New("key or signature is malformed")
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), signingInput, sig) {
			return errBadSignature
		}
		return nil
	}
	return errors.New("unsupported signing algorithm")
}

// verifyIDToken verifies an OIDC ID token against a static JWKS and returns its claims.
func verifyIDToken(idToken string, jwks map[string]any, issuer, aud string, now int64) (map[string]any, *EngineError) {
	bad := func(msg string) (map[string]any, *EngineError) { return nil, newErr("id_token_invalid", msg) }
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return bad("not a JWT")
	}
	headRaw, err1 := b64uDec(parts[0])
	sig, err2 := b64uDec(parts[2])
	if err1 != nil || err2 != nil {
		return bad("not a JWT")
	}
	headAny, err := parseJSONBytes(headRaw)
	header, ok := headAny.(map[string]any)
	if err != nil || !ok {
		return bad("not a JWT")
	}
	alg, has := header["alg"]
	if !has {
		return bad("not a JWT")
	}
	var keys []map[string]any
	if list, ok := jwks["keys"].([]any); ok {
		for _, k := range list {
			if km, ok := k.(map[string]any); ok {
				keys = append(keys, km)
			}
		}
	}
	var jwk map[string]any
	if kid := header["kid"]; truthy(kid) {
		for _, k := range keys {
			if v, has := k["kid"]; has && jsonKind(v) == jsonKind(kid) && pyEqual(v, kid) {
				jwk = k
				break
			}
		}
	} else if len(keys) == 1 {
		jwk = keys[0]
	}
	if jwk == nil {
		return bad("no matching key in the JWKS")
	}
	if err := verifyJWS(alg, jwk, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return bad(err.Error())
	}
	bodyRaw, err := b64uDec(parts[1])
	if err != nil {
		return bad("malformed claims")
	}
	claimsAny, err := parseJSONBytes(bodyRaw)
	claims, ok := claimsAny.(map[string]any)
	if err != nil || !ok {
		return bad("malformed claims")
	}
	if iss, ok := claims["iss"].(string); !ok || iss != issuer {
		return bad("wrong issuer")
	}
	audOK := false
	switch a := claims["aud"].(type) {
	case string:
		audOK = a == aud
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == aud {
				audOK = true
			}
		}
	}
	if !audOK {
		return bad("wrong audience")
	}
	// OIDC Core 3.1.3.7: a token issued to another client is not ours even when
	// our client id is among its audiences (access tokens of other clients are)
	azp, hasAzp := claims["azp"]
	if s, isStr := azp.(string); hasAzp && (!isStr || s != aud) {
		return bad("issued to another client (azp)")
	}
	if list, isList := claims["aud"].([]any); isList && len(list) > 1 && !hasAzp {
		return bad("several audiences and no azp claim")
	}
	if !isInt(claims["exp"]) {
		return bad("no exp claim")
	}
	if exp, ok := claims["exp"].(int64); ok && exp <= now || !ok && claims["exp"].(*big.Int).Sign() < 0 {
		return bad("ID token has expired")
	}
	switch nbf := claims["nbf"].(type) {
	case int64:
		if nbf > satAdd(now, 60) {
			return bad("ID token is not valid yet")
		}
	case *big.Int:
		if nbf.Sign() > 0 {
			return bad("ID token is not valid yet")
		}
	}
	return claims, nil
}

func satAdd(a, b int64) int64 {
	s, err := addChecked(a, b)
	if err != nil {
		if b > 0 {
			return 1<<63 - 1
		}
		return -1 << 63
	}
	return s
}

func satSub(a, b int64) int64 {
	d, err := subChecked(a, b)
	if err != nil {
		if b < 0 {
			return 1<<63 - 1
		}
		return -1 << 63
	}
	return d
}
