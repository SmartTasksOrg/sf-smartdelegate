package smartdelegate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The conformance vectors only carry RS256 ID tokens. This test makes its own
// keys and tokens for every algorithm the reference accepts (RS256/384/512,
// ES256/384, EdDSA), checks what this port says about each, and - when the
// Python reference is available - that the reference says the same.

type idpKeys struct {
	rsa  *rsa.PrivateKey
	p256 *ecdsa.PrivateKey
	p384 *ecdsa.PrivateKey
	ed   ed25519.PrivateKey
}

func (k *idpKeys) jwks() map[string]any {
	ec := func(kid, crv string, key *ecdsa.PrivateKey, size int) map[string]any {
		return map[string]any{"kty": "EC", "kid": kid, "crv": crv, "x": b64u(key.X.FillBytes(make([]byte, size))), "y": b64u(key.Y.FillBytes(make([]byte, size)))}
	}
	return map[string]any{"keys": []any{
		map[string]any{"kty": "RSA", "kid": "rsa", "n": b64u(k.rsa.N.Bytes()), "e": b64u(big.NewInt(int64(k.rsa.E)).Bytes())},
		ec("p256", "P-256", k.p256, 32), ec("p384", "P-384", k.p384, 48),
		map[string]any{"kty": "OKP", "kid": "ed", "crv": "Ed25519", "x": b64u(k.ed.Public().(ed25519.PublicKey))},
		map[string]any{"kty": "OKP", "kid": "ed448", "crv": "Ed448", "x": b64u(k.ed.Public().(ed25519.PublicKey))},
		map[string]any{"kty": "oct", "kid": "secret", "k": b64u([]byte("0123456789abcdef0123456789abcdef"))},
		"not a key",
	}}
}

func digestFor(alg string, data []byte) (crypto.Hash, []byte) {
	switch alg[2:] {
	case "384":
		s := sha512.Sum384(data)
		return crypto.SHA384, s[:]
	case "512":
		s := sha512.Sum512(data)
		return crypto.SHA512, s[:]
	}
	s := sha256.Sum256(data)
	return crypto.SHA256, s[:]
}

// sign makes a JWS. `signAs` is the algorithm actually used to sign, which a
// test may make differ from the header.
func (k *idpKeys) sign(t *testing.T, header, claims map[string]any, signAs string) string {
	t.Helper()
	input := b64u(MarshalJSON(header)) + "." + b64u(MarshalJSON(claims))
	var sig []byte
	var err error
	switch signAs {
	case "RS256", "RS384", "RS512":
		hash, sum := digestFor(signAs, []byte(input))
		sig, err = rsa.SignPKCS1v15(rand.Reader, k.rsa, hash, sum)
	case "ES256", "ES384", "ES256-DER":
		key, size := k.p256, 32
		if signAs == "ES384" {
			key, size = k.p384, 48
		}
		_, sum := digestFor(strings.TrimSuffix(signAs, "-DER"), []byte(input))
		r, s, e := ecdsa.Sign(rand.Reader, key, sum)
		err = e
		if signAs == "ES256-DER" {
			sig, _ = asn1.Marshal(struct{ R, S *big.Int }{r, s})
		} else if e == nil {
			sig = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
		}
	case "EdDSA":
		sig = ed25519.Sign(k.ed, []byte(input))
	default:
		sig = []byte("no signature at all")
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64u(sig)
}

func TestIDTokenAlgorithms(t *testing.T) {
	keys := &idpKeys{}
	var err error
	if keys.rsa, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if keys.p256, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if keys.p384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if _, keys.ed, err = ed25519.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	const issuer, aud = "https://idp.example.test", "client-1"
	claims := func(change map[string]any) map[string]any {
		c := map[string]any{"iss": issuer, "aud": aud, "sub": "alice", "exp": testNow + 600, "iat": testNow, "groups": []any{"support"}}
		for k, v := range change {
			if v == nil {
				delete(c, k)
			} else {
				c[k] = v
			}
		}
		return c
	}
	head := func(alg, kid string) map[string]any {
		h := map[string]any{"typ": "JWT"}
		if alg != "" {
			h["alg"] = alg
		}
		if kid != "" {
			h["kid"] = kid
		}
		return h
	}
	kidOf := map[string]string{"RS256": "rsa", "RS384": "rsa", "RS512": "rsa", "ES256": "p256", "ES384": "p384", "EdDSA": "ed"}
	type tokenCase struct {
		name, token, want string // want: "" for ok, else the error code
		extra             map[string]any
	}
	var cases []tokenCase
	add := func(name, want, token string) { cases = append(cases, tokenCase{name: name, token: token, want: want}) }
	for alg, kid := range kidOf {
		good := keys.sign(t, head(alg, kid), claims(nil), alg)
		add(alg+" valid", "", good)
		parts := strings.Split(good, ".")
		add(alg+" other payload", "id_token_invalid", parts[0]+"."+b64u(MarshalJSON(claims(map[string]any{"sub": "bob"})))+"."+parts[2])
		add(alg+" other header", "id_token_invalid", b64u(MarshalJSON(map[string]any{"alg": alg, "kid": kid}))+"."+parts[1]+"."+parts[2])
		add(alg+" truncated signature", "id_token_invalid", good[:len(good)-4])
		add(alg+" no signature", "id_token_invalid", parts[0]+"."+parts[1]+".")
		add(alg+" junk signature", "id_token_invalid", keys.sign(t, head(alg, kid), claims(nil), "none"))
		add(alg+" unknown kid", "id_token_invalid", keys.sign(t, head(alg, "nobody"), claims(nil), alg))
		add(alg+" no kid, several keys", "id_token_invalid", keys.sign(t, head(alg, ""), claims(nil), alg))
		for other, otherKid := range kidOf {
			if otherKid != kid {
				add(alg+" with the key of "+other, "id_token_invalid", keys.sign(t, head(alg, otherKid), claims(nil), alg))
			}
		}
		add(alg+" with a symmetric key", "id_token_invalid", keys.sign(t, head(alg, "secret"), claims(nil), alg))
	}
	add("RS256 header, signed as RS384", "id_token_invalid", keys.sign(t, head("RS256", "rsa"), claims(nil), "RS384"))
	add("ES256 with a DER signature", "id_token_invalid", keys.sign(t, head("ES256", "p256"), claims(nil), "ES256-DER"))
	add("EdDSA with an Ed448 key entry", "id_token_invalid", keys.sign(t, head("EdDSA", "ed448"), claims(nil), "EdDSA"))
	for _, alg := range []string{"none", "HS256", "PS256", "ES512", "RS1", "rs256", ""} {
		add("alg "+alg, "id_token_invalid", keys.sign(t, head(alg, "rsa"), claims(nil), "RS256"))
	}
	add("alg is a number", "id_token_invalid", keys.sign(t, map[string]any{"alg": 256, "kid": "rsa"}, claims(nil), "RS256"))
	add("kid is a number", "id_token_invalid", keys.sign(t, map[string]any{"alg": "RS256", "kid": 5}, claims(nil), "RS256"))
	good := keys.sign(t, head("ES256", "p256"), claims(nil), "ES256")
	add("two parts", "id_token_invalid", good[:strings.LastIndex(good, ".")])
	add("four parts", "id_token_invalid", good+".x")
	add("padded", "id_token_invalid", good+"=")
	add("header is not JSON", "id_token_invalid", b64u([]byte("{"))+good[strings.Index(good, "."):])
	add("header is a list", "id_token_invalid", b64u([]byte(`["RS256"]`))+good[strings.Index(good, "."):])

	claimCase := func(name, want string, change map[string]any) {
		add("claims: "+name, want, keys.sign(t, head("EdDSA", "ed"), claims(change), "EdDSA"))
	}
	claimCase("aud is a list of one, the audience", "", map[string]any{"aud": []any{aud}})
	claimCase("aud is a list holding the audience, no azp", "id_token_invalid", map[string]any{"aud": []any{"other", aud}})
	claimCase("aud is a list holding the audience, azp is the audience", "", map[string]any{"aud": []any{"other", aud}, "azp": aud})
	claimCase("aud is a list without it", "id_token_invalid", map[string]any{"aud": []any{"other"}})
	claimCase("aud is a number", "id_token_invalid", map[string]any{"aud": 5})
	claimCase("aud missing", "id_token_invalid", map[string]any{"aud": nil})
	claimCase("another issuer", "id_token_invalid", map[string]any{"iss": issuer + "/"})
	claimCase("iss missing", "id_token_invalid", map[string]any{"iss": nil})
	claimCase("exp missing", "id_token_invalid", map[string]any{"exp": nil})
	claimCase("exp is a float", "id_token_invalid", map[string]any{"exp": float64(testNow + 600)})
	claimCase("exp is a string", "id_token_invalid", map[string]any{"exp": "4102444800"})
	claimCase("exp is true", "id_token_invalid", map[string]any{"exp": true})
	claimCase("exp is now", "id_token_invalid", map[string]any{"exp": testNow})
	claimCase("exp is now + 1", "", map[string]any{"exp": testNow + 1})
	claimCase("exp beyond 64 bits", "", map[string]any{"exp": new(big.Int).Lsh(big.NewInt(1), 70)})
	claimCase("nbf 60 seconds ahead", "", map[string]any{"nbf": testNow + 60})
	claimCase("nbf 61 seconds ahead", "id_token_invalid", map[string]any{"nbf": testNow + 61})
	claimCase("nbf is a string", "", map[string]any{"nbf": "later"})
	claimCase("nbf is a float", "", map[string]any{"nbf": float64(testNow + 9999)})
	claimCase("sub missing", "id_token_invalid", map[string]any{"sub": nil})
	claimCase("sub empty", "id_token_invalid", map[string]any{"sub": ""})
	claimCase("sub is a number", "id_token_invalid", map[string]any{"sub": 5})
	claimCase("a user entities.json does not know, in a group by the claim", "", map[string]any{"sub": "zed"})
	claimCase("a user entities.json does not know, in no group", "delegation_denied", map[string]any{"sub": "zed", "groups": []any{"nope"}})
	claimCase("groups missing: member of nothing", "delegation_denied", map[string]any{"groups": nil})
	claimCase("groups empty", "delegation_denied", map[string]any{"groups": []any{}})
	claimCase("groups is one name", "", map[string]any{"groups": "support"})
	claimCase("groups as {type, id}", "", map[string]any{"groups": []any{map[string]any{"type": "Group", "id": "support"}, "nope", "support"}})
	claimCase("groups is a number", "id_token_invalid", map[string]any{"groups": 5})
	claimCase("groups holds a number", "id_token_invalid", map[string]any{"groups": []any{"support", 5}})
	claimCase("groups is an object", "id_token_invalid", map[string]any{"groups": map[string]any{"support": true}})
	claimCase("live groups replace stored ones", "delegation_denied", map[string]any{"groups": []any{"supervisors"}})
	cases = append(cases,
		tokenCase{name: "`user` equal to the token's", token: good, extra: map[string]any{"user": "alice"}},
		tokenCase{name: "`user` different from the token's", token: good, want: "id_token_invalid", extra: map[string]any{"user": "bob"}},
		tokenCase{name: "`groups` in the request is ignored", token: good, extra: map[string]any{"groups": []any{5}}},
		tokenCase{name: "a role held through the claim", token: keys.sign(t, head("ES384", "p384"), claims(map[string]any{"sub": "dave", "groups": []any{"support", "supervisors"}}), "ES384"),
			extra: map[string]any{"role": "supervisor", "task": "escalation-1"}},
		tokenCase{name: "a role not held through the claim", token: good, want: "role_not_held", extra: map[string]any{"role": "supervisor", "task": "escalation-1"}},
	)

	config := func(state string) map[string]any {
		return ConformanceConfig(specBundle(t), state, map[string]any{"idp": map[string]any{"issuer": issuer, "audience": aud, "jwks": keys.jwks(), "groups_claim": "groups"}})
	}
	request := func(c tokenCase) map[string]any {
		in := map[string]any{"id_token": c.token, "agent": "support-bot", "cap": fullCap(), "now": testNow}
		for k, v := range c.extra {
			in[k] = v
		}
		if _, has := c.extra["role"]; has {
			delete(in, "cap")
		}
		return in
	}
	e, err := NewEngine(config(filepath.Join(t.TempDir(), "state")))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	results := make([]map[string]any, len(cases))
	accepted := 0
	for i, c := range cases {
		results[i] = e.Call("issue_token", request(c))
		if got := errCode(results[i]); got != c.want || (c.want == "") != (results[i]["ok"] == true) {
			t.Errorf("%s: got %s, want %q", c.name, Canon(results[i]), c.want)
		}
		if results[i]["ok"] == true {
			accepted++
		}
	}
	if accepted < 15 {
		t.Errorf("only %d of %d ID tokens were accepted; the valid ones must be", accepted, len(cases))
	}

	// one key and no kid in the header: that key is used; a kid then matches nothing
	single := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64u(keys.ed.Public().(ed25519.PublicKey))}}}
	one, err := NewEngine(ConformanceConfig(specBundle(t), "", map[string]any{"idp": map[string]any{"issuer": issuer, "audience": aud, "jwks": single, "user_claim": "email"}}))
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	withEmail := claims(map[string]any{"email": "alice", "sub": "someone-else", "groups": []any{}})
	if r := one.Call("issue_token", map[string]any{"id_token": keys.sign(t, head("EdDSA", ""), withEmail, "EdDSA"), "agent": "support-bot", "cap": fullCap(), "now": testNow}); r["ok"] != true || r["user"] != "alice" {
		t.Errorf("one key, no kid, user_claim email (no groups_claim: stored membership): %s", Canon(r))
	}
	if r := one.Call("issue_token", map[string]any{"id_token": keys.sign(t, head("EdDSA", "ed"), withEmail, "EdDSA"), "agent": "support-bot", "cap": fullCap(), "now": testNow}); errCode(r) != "id_token_invalid" {
		t.Errorf("a kid that no key carries: %s", Canon(r))
	}
	if r := one.Call("issue_token", map[string]any{"id_token": keys.sign(t, head("EdDSA", ""), claims(nil), "EdDSA"), "agent": "support-bot", "cap": fullCap(), "now": testNow}); errCode(r) != "id_token_invalid" {
		t.Errorf("no `email` claim: %s", Canon(r))
	}
	t.Logf("ID tokens: %d cases, %d accepted", len(cases), accepted)

	t.Run("the reference agrees", func(t *testing.T) {
		needPython(t)
		ref := startPython(t, engineScript)
		started := ref.line(Canon(map[string]any{"new": config(filepath.Join(t.TempDir(), "state"))}))
		if !strings.Contains(started, `"ok": true`) {
			t.Fatalf("the reference did not start: %s", started)
		}
		for i, c := range cases {
			theirs := mustParse(t, ref.line(Canon(map[string]any{"op": "issue_token", "input": request(c)}))).(map[string]any)
			mine := results[i]
			for _, r := range []map[string]any{mine, theirs} {
				delete(r, "token")
				delete(r, "token_id")
			}
			if a, b := Canon(scrub(mine, nil)), Canon(scrub(theirs, nil)); a != b {
				t.Errorf("%s:\n  go        %s\n  reference %s", c.name, a, b)
			}
		}
	})
}

// The rules added after the first run against a real identity provider
// (spec/PORTING.md, "OIDC ID tokens"): authorised party, the revoked-user
// cut-off against the ID token's iat, a nested group claim, and reload
// re-reading idp.jwks_file. Every step is also given to the reference.
func TestIDTokenProviderRules(t *testing.T) {
	const issuer, aud = "https://idp.example.test", "client-1"
	newKey := func(kid string) (*idpKeys, map[string]any) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return &idpKeys{ed: priv}, map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": kid, "crv": "Ed25519", "x": b64u(priv.Public().(ed25519.PublicKey))}}}
	}
	keyA, jwksA := newKey("a")
	keyB, jwksB := newKey("b")
	token := func(k *idpKeys, kid string, change map[string]any) string {
		c := map[string]any{"iss": issuer, "aud": aud, "sub": "alice", "exp": testNow + 6000, "iat": testNow, "realm_access": map[string]any{"roles": []any{"support"}}}
		for key, v := range change {
			if v == "<absent>" {
				delete(c, key)
			} else {
				c[key] = v
			}
		}
		return k.sign(t, map[string]any{"alg": "EdDSA", "kid": kid}, c, "EdDSA")
	}
	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "bundle")
	copyDir(t, specBundle(t), bundleDir)
	jwksFile := filepath.Join(dir, "jwks.json")
	writeJSONFile(t, jwksFile, jwksA)
	signingKey, _, _ := Keygen()
	config := func(state string) map[string]any {
		return map[string]any{"bundle_dir": bundleDir, "state_dir": state, "allow_test_clock": true, "signing_key": signingKey,
			"idp": map[string]any{"issuer": issuer, "audience": aud, "jwks_file": jwksFile, "groups_claim": "realm_access.roles"}}
	}
	type step struct {
		name string
		do   func() // a change on disk, seen by both engines
		op   string // or an operation
		in   map[string]any
		want string // "" for ok, else the error code
	}
	var steps []step
	issue := func(name, want string, k *idpKeys, kid string, change map[string]any, now int64) {
		steps = append(steps, step{name: name, op: "issue_token", want: want,
			in: map[string]any{"id_token": token(k, kid, change), "agent": "support-bot", "cap": fullCap(), "now": now}})
	}
	file := func(name string, do func()) { steps = append(steps, step{name: name, do: do}) }
	reload := func(name, want string) {
		steps = append(steps, step{name: name, op: "reload", in: map[string]any{}, want: want})
	}
	inv := "id_token_invalid"

	// authorised party
	issue("no azp, aud a string", "", keyA, "a", nil, testNow)
	issue("azp is the audience", "", keyA, "a", map[string]any{"azp": aud}, testNow)
	issue("azp is another client", inv, keyA, "a", map[string]any{"azp": "client-2"}, testNow)
	issue("azp null", inv, keyA, "a", map[string]any{"azp": nil}, testNow)
	issue("azp a number", inv, keyA, "a", map[string]any{"azp": 5}, testNow)
	issue("azp a list holding the audience", inv, keyA, "a", map[string]any{"azp": []any{aud}}, testNow)
	issue("azp empty", inv, keyA, "a", map[string]any{"azp": ""}, testNow)
	issue("aud a list of one, no azp", "", keyA, "a", map[string]any{"aud": []any{aud}}, testNow)
	issue("aud a list of one, azp another client", inv, keyA, "a", map[string]any{"aud": []any{aud}, "azp": "client-2"}, testNow)
	issue("several audiences, no azp", inv, keyA, "a", map[string]any{"aud": []any{aud, "account"}}, testNow)
	issue("several audiences, azp is the audience", "", keyA, "a", map[string]any{"aud": []any{"account", aud, "x"}, "azp": aud}, testNow)
	issue("several audiences, azp another of them", inv, keyA, "a", map[string]any{"aud": []any{"account", aud}, "azp": "account"}, testNow)
	issue("the audience twice, no azp", inv, keyA, "a", map[string]any{"aud": []any{aud, aud}}, testNow)
	issue("several audiences without ours, azp ours", inv, keyA, "a", map[string]any{"aud": []any{"account", "x"}, "azp": aud}, testNow)
	issue("aud an empty list", inv, keyA, "a", map[string]any{"aud": []any{}}, testNow)

	// nested group claim
	issue("nested claim", "", keyA, "a", nil, testNow)
	issue("nested claim, one name", "", keyA, "a", map[string]any{"realm_access": map[string]any{"roles": "support"}}, testNow)
	issue("a top-level claim with the dotted name wins", "", keyA, "a", map[string]any{"realm_access.roles": []any{"support"}, "realm_access": map[string]any{"roles": []any{"nope"}}}, testNow)
	issue("a top-level claim with the dotted name wins, also when it grants nothing", "delegation_denied", keyA, "a", map[string]any{"realm_access.roles": []any{}}, testNow)
	issue("a top-level null falls through to the path", "", keyA, "a", map[string]any{"realm_access.roles": nil}, testNow)
	issue("the path is absent: member of nothing", "delegation_denied", keyA, "a", map[string]any{"realm_access": "<absent>"}, testNow)
	issue("the path leads through a string", "delegation_denied", keyA, "a", map[string]any{"realm_access": "roles"}, testNow)
	issue("the path leads through a list", "delegation_denied", keyA, "a", map[string]any{"realm_access": []any{map[string]any{"roles": []any{"support"}}}}, testNow)
	issue("the last key is absent", "delegation_denied", keyA, "a", map[string]any{"realm_access": map[string]any{"role": []any{"support"}}}, testNow)
	issue("the nested value is null", "delegation_denied", keyA, "a", map[string]any{"realm_access": map[string]any{"roles": nil}}, testNow)
	issue("the nested value is a number", inv, keyA, "a", map[string]any{"realm_access": map[string]any{"roles": 5}}, testNow)
	issue("the nested value is an object", inv, keyA, "a", map[string]any{"realm_access": map[string]any{"roles": map[string]any{"support": true}}}, testNow)
	issue("the `groups` claim is not the configured one", "delegation_denied", keyA, "a", map[string]any{"realm_access": "<absent>", "groups": []any{"support"}}, testNow)

	// revoked users: the ID token's iat against the cut-off
	steps = append(steps, step{name: "revoke alice", op: "revoke", in: map[string]any{"user": "alice", "by": "hr", "now": testNow + 100}})
	issue("iat before the cut-off", inv, keyA, "a", nil, testNow+200)
	issue("iat at the cut-off", inv, keyA, "a", map[string]any{"iat": testNow + 100}, testNow+200)
	issue("iat after the cut-off", "", keyA, "a", map[string]any{"iat": testNow + 101}, testNow+200)
	issue("no iat", inv, keyA, "a", map[string]any{"iat": "<absent>"}, testNow+200)
	issue("iat a string", inv, keyA, "a", map[string]any{"iat": "1800000000"}, testNow+200)
	issue("iat a float", inv, keyA, "a", map[string]any{"iat": float64(testNow + 150)}, testNow+200)
	issue("iat true", inv, keyA, "a", map[string]any{"iat": true}, testNow+200)
	issue("iat null", inv, keyA, "a", map[string]any{"iat": nil}, testNow+200)
	issue("another user is not affected", "", keyA, "a", map[string]any{"sub": "bob"}, testNow+200)
	issue("another user without iat, not revoked", "", keyA, "a", map[string]any{"sub": "erin", "iat": "<absent>"}, testNow+200)
	steps = append(steps, step{name: "revoke alice with an earlier clock", op: "revoke", in: map[string]any{"user": "alice", "now": testNow + 5}})
	issue("the cut-off did not move back", inv, keyA, "a", map[string]any{"iat": testNow + 50}, testNow+200)
	steps = append(steps, step{name: "with `user`, the admin path: not an ID token matter", op: "issue_token",
		in: map[string]any{"user": "alice", "agent": "support-bot", "cap": fullCap(), "now": testNow + 200}})

	// reload re-reads idp.jwks_file
	issue("key b before the rotation", inv, keyB, "b", map[string]any{"sub": "bob"}, testNow)
	file("the provider rotates to key b", func() { writeJSONFile(t, jwksFile, jwksB) })
	issue("the file changed but nothing was reloaded: key b", inv, keyB, "b", map[string]any{"sub": "bob"}, testNow)
	issue("the file changed but nothing was reloaded: key a", "", keyA, "a", map[string]any{"sub": "bob"}, testNow)
	reload("reload", "")
	issue("after the reload: key b", "", keyB, "b", map[string]any{"sub": "bob"}, testNow)
	issue("after the reload: key a", inv, keyA, "a", map[string]any{"sub": "bob"}, testNow)
	for name, content := range map[string]string{"not JSON": "{", "a list": "[]", "keys not a list": `{"keys": {}}`, "no keys": `{}`, "null": "null", "not UTF-8": "{\"keys\": [\"\xff\"]}", "empty": ""} {
		content := content
		file("jwks file: "+name, func() {
			if err := os.WriteFile(jwksFile, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		})
		reload("reload with a jwks file that is "+name, "invalid_config")
		issue("the old keys stay after a failed reload ("+name+"): key b", "", keyB, "b", map[string]any{"sub": "bob"}, testNow)
	}
	file("jwks file removed", func() { _ = os.Remove(jwksFile) })
	reload("reload without the jwks file", "invalid_config")
	issue("the old keys stay: key b", "", keyB, "b", map[string]any{"sub": "bob"}, testNow)
	// a bundle that fails to load: the new keys are not taken either
	roles := filepath.Join(bundleDir, "roles.json")
	goodRoles, _ := os.ReadFile(roles)
	file("key a again, and a broken bundle", func() {
		writeJSONFile(t, jwksFile, jwksA)
		if err := os.WriteFile(roles, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	reload("reload with a broken bundle", "roles_parse")
	issue("neither bundle nor keys were replaced: key b", "", keyB, "b", map[string]any{"sub": "bob"}, testNow)
	issue("neither bundle nor keys were replaced: key a", inv, keyA, "a", map[string]any{"sub": "bob"}, testNow)
	file("a broken jwks file, and a changed bundle", func() {
		if err := os.WriteFile(roles, []byte(`{"roles": {}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(jwksFile, []byte("["), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	reload("reload with a broken jwks file", "invalid_config")
	steps = append(steps, step{name: "the old bundle is still in force (its roles)", op: "info", in: map[string]any{}})
	file("both repaired", func() {
		writeJSONFile(t, jwksFile, jwksA)
		if err := os.WriteFile(roles, goodRoles, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	reload("reload", "")
	issue("after the second rotation: key a", "", keyA, "a", map[string]any{"sub": "bob"}, testNow)
	issue("after the second rotation: key b", inv, keyB, "b", map[string]any{"sub": "bob"}, testNow)

	e, err := NewEngine(config(filepath.Join(dir, "go")))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var ref *refProcess
	if havePython(t) {
		ref = startPython(t, engineScript)
		if started := ref.line(Canon(map[string]any{"new": config(filepath.Join(dir, "reference"))})); !strings.Contains(started, `"ok": true`) {
			t.Fatalf("the reference did not start: %s", started)
		}
	} else {
		t.Logf("not compared with the Python reference: %s", pyReason)
	}
	ran, mismatches := 0, 0
	rolesBefore := ""
	for _, s := range steps {
		if s.do != nil {
			s.do()
			continue
		}
		ran++
		mine := e.Call(s.op, s.in)
		if s.op == "issue_token" || s.op == "reload" {
			if got := errCode(mine); got != s.want || (s.want == "") != (mine["ok"] == true) {
				t.Errorf("%s: got %s, want %q", s.name, Canon(mine), s.want)
			}
		}
		if s.op == "info" {
			if rolesBefore = Canon(mine["roles"]); !strings.Contains(rolesBefore, "support-agent") {
				t.Errorf("%s: %s", s.name, rolesBefore)
			}
		}
		if ref == nil {
			continue
		}
		theirs := mustParse(t, ref.line(Canon(map[string]any{"op": s.op, "input": s.in}))).(map[string]any)
		for _, r := range []map[string]any{mine, theirs} {
			delete(r, "token")
			delete(r, "token_id")
		}
		if a, b := Canon(scrub(mine, nil)), Canon(scrub(theirs, nil)); a != b {
			mismatches++
			t.Errorf("%s:\n  go        %.700s\n  reference %.700s", s.name, a, b)
		}
	}
	// keys given inline: reload has no file to read, and works
	inline, err := NewEngine(map[string]any{"bundle_dir": bundleDir, "allow_test_clock": true,
		"idp": map[string]any{"issuer": issuer, "audience": aud, "jwks": jwksB, "jwks_file": filepath.Join(dir, "does-not-exist.json")}})
	if err != nil {
		t.Fatal(err)
	}
	defer inline.Close()
	if r := inline.Call("reload", map[string]any{}); r["ok"] != true {
		t.Errorf("reload with inline keys: %s", Canon(r))
	}
	if r := inline.Call("issue_token", map[string]any{"id_token": token(keyB, "b", map[string]any{"sub": "bob"}), "agent": "support-bot", "cap": fullCap(), "now": testNow}); r["ok"] != true {
		t.Errorf("inline keys after a reload: %s", Canon(r))
	}
	t.Logf("ID token provider rules: %d steps; compared with the reference: %v, %d mismatches", ran, ref != nil, mismatches)
}
