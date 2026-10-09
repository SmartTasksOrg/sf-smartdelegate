package smartdelegate

// Policy bundle: compiled policies, entity store, field catalog, signature.
//
//	bundle/
//	  policies.json     Cedar's JSON policy form, keyed by policy id. This is
//	                    what the engine evaluates.
//	  policies/*.cedar  the human-written source policies.json is compiled from
//	                    (`smartdelegate bundle compile`, in the Rust port)
//	  entities.json     users, groups, agents
//	  catalog.json      resources, fields, classification labels
//	  roles.json        roles a human can act in (optional)
//	  tests/*.json      policy unit tests (not part of the version)
//	  bundle.sig.json   file hashes + Ed25519 signature

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

func readText(path string) (string, *EngineError) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", newErr("bundle_io", path+": "+ioMessage(err))
	}
	if !utf8.Valid(raw) {
		return "", newErr("bundle_io", path+": not UTF-8")
	}
	return string(raw), nil
}

func ioMessage(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func digestFile(path string) (string, *EngineError) {
	text, err := readText(path)
	if err != nil {
		return "", err
	}
	return sha256Hex([]byte(strings.ReplaceAll(text, "\r\n", "\n"))), nil
}

// Manifest maps a relative path to the sha256 of every file that defines
// behaviour. Line endings are normalised so a Windows checkout has the same
// version.
func Manifest(dir string) (map[string]string, error) {
	files, err := manifest(dir)
	if err != nil {
		return nil, err
	}
	return files, nil
}

func manifest(dir string) (map[string]string, *EngineError) {
	files := map[string]string{}
	p := filepath.Join(dir, "policies.json")
	if !exists(p) {
		return nil, newErr("bundle_io", p+": missing. This port loads compiled policies; run `smartdelegate bundle compile` (Rust port) on the .cedar sources")
	}
	for _, name := range []string{"policies.json", "entities.json", "catalog.json", "roles.json"} {
		if exists(filepath.Join(dir, name)) {
			d, err := digestFile(filepath.Join(dir, name))
			if err != nil {
				return nil, err
			}
			files[name] = d
		}
	}
	return files, nil
}

func stringMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// VersionOf is the bundle version: sha256 of the canonical manifest.
func VersionOf(files map[string]string) string {
	return hashValue(stringMap(files))
}

// ---- keys ------------------------------------------------------------------

var pkcs8Prefix, _ = hex.DecodeString("302e020100300506032b657004220420")

// Keygen makes an Ed25519 key pair: (private, public), both base64. The
// private key is the PKCS#8 version 1 DER; the public key is the 32 raw bytes.
func Keygen() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	der := append(append([]byte{}, pkcs8Prefix...), priv.Seed()...)
	return base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(pub), nil
}

func loadPrivate(b64 string) (ed25519.PrivateKey, *EngineError) {
	der, err := b64Strict(strip(b64))
	if err != nil {
		return nil, newErr("crypto", "private key is not base64 Ed25519 PKCS#8")
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, newErr("crypto", "private key is not base64 Ed25519 PKCS#8")
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, newErr("crypto", "private key is not Ed25519")
	}
	return priv, nil
}

func loadPublic(b64 string) (ed25519.PublicKey, *EngineError) {
	raw, err := b64Strict(strip(b64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, newErr("crypto", "public key is not base64 of 32 raw Ed25519 bytes")
	}
	return ed25519.PublicKey(raw), nil
}

// KeyID is the first 16 hex characters of sha256(raw public key).
func KeyID(publicB64 string) (string, error) {
	pub, err := loadPublic(publicB64)
	if err != nil {
		return "", err
	}
	return sha256Hex(pub)[:16], nil
}

// SignBundle signs the bundle in dir and writes bundle.sig.json. It returns
// what it wrote: files, version, key_id, alg, signature.
func SignBundle(dir, privateB64 string) (map[string]any, error) {
	key, kerr := loadPrivate(privateB64)
	if kerr != nil {
		return nil, kerr
	}
	files, merr := manifest(dir)
	if merr != nil {
		return nil, merr
	}
	version := VersionOf(files)
	pub := key.Public().(ed25519.PublicKey)
	payload := map[string]any{"files": stringMap(files), "version": version}
	out := map[string]any{"files": stringMap(files), "version": version, "key_id": sha256Hex(pub)[:16], "alg": "Ed25519",
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(Canon(payload))))}
	if err := os.WriteFile(filepath.Join(dir, "bundle.sig.json"), []byte(MarshalIndent(out)), 0o644); err != nil {
		return nil, err
	}
	return out, nil
}

func verifyBundleSignature(dir string, files map[string]string, publicB64 string) *EngineError {
	p := filepath.Join(dir, "bundle.sig.json")
	if !exists(p) {
		return newErr("bundle_unsigned", "a signed bundle is required, but bundle.sig.json is missing")
	}
	malformed := newErr("bundle_signature", "bundle.sig.json is malformed")
	text, rerr := readText(p)
	if rerr != nil {
		return malformed
	}
	doc, err := ParseJSON([]byte(text))
	sig, ok := doc.(map[string]any)
	if err != nil || !ok {
		return malformed
	}
	sigText, ok := sig["signature"].(string)
	if _, has := sig["signature"]; has && !ok {
		return malformed
	}
	rawSig, err := b64Strict(sigText)
	if err != nil {
		return malformed
	}
	payload := map[string]any{"files": sig["files"], "version": sig["version"]}
	pub, kerr := loadPublic(publicB64)
	if kerr != nil {
		return kerr
	}
	if !ed25519.Verify(pub, []byte(Canon(payload)), rawSig) {
		return newErr("bundle_signature", "bundle signature does not verify with the configured key")
	}
	if !pyEqual(stringMap(files), sig["files"]) {
		return newErr("bundle_signature", "bundle files changed after signing")
	}
	return nil
}

type fieldDef struct {
	labels []any
	mask   string // "", "drop" or "redact"
}

type resourceDef struct {
	entityType string
	fields     map[string]*fieldDef
}

// Bundle is a loaded policy bundle.
type Bundle struct {
	Dir      string
	Version  string
	SignedBy string // key id, or "" when no signature was required
	Policies map[string]*Policy
	Roles    map[string]*Role

	store   *Store
	attrs   map[string]any // "Type::id" -> attrs exactly as written in entities.json
	catalog map[string]*resourceDef
}

// LoadBundle loads the bundle in dir. When publicKey is not empty the bundle
// must carry a valid signature by that key or loading fails.
func LoadBundle(dir, publicKey string) (*Bundle, error) {
	b, err := loadBundle(dir, publicKey)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func loadBundle(dir, publicKey string) (*Bundle, *EngineError) {
	b := &Bundle{Dir: dir, Policies: map[string]*Policy{}, Roles: map[string]*Role{}, attrs: map[string]any{}, catalog: map[string]*resourceDef{}}
	files, err := manifest(dir)
	if err != nil {
		return nil, err
	}
	b.Version = VersionOf(files)
	if publicKey != "" {
		if err := verifyBundleSignature(dir, files, publicKey); err != nil {
			return nil, err
		}
		pub, err := loadPublic(publicKey)
		if err != nil {
			return nil, err
		}
		b.SignedBy = sha256Hex(pub)[:16]
	}

	text, err := readText(filepath.Join(dir, "policies.json"))
	if err != nil {
		return nil, err
	}
	parsed, perr := ParseJSON([]byte(text))
	if perr != nil {
		return nil, newErr("policy_parse", "policies.json: "+perr.Error())
	}
	doc, _ := parsed.(map[string]any)
	compiled, ok := doc["policies"].(map[string]any)
	if !ok {
		return nil, newErr("policy_parse", "policies.json: expected {\"policies\": {...}}")
	}
	// policies.json records the hash of each .cedar file it was compiled
	// from. This port cannot parse Cedar text, but it can tell when a source
	// was edited (or added) without recompiling, so the policy a reviewer
	// reads is the policy that runs.
	sources, _ := doc["sources"].(map[string]any)
	onDisk := map[string]any{}
	if entries, derr := os.ReadDir(filepath.Join(dir, "policies")); derr == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".cedar") {
				d, err := digestFile(filepath.Join(dir, "policies", e.Name()))
				if err != nil {
					return nil, err
				}
				onDisk["policies/"+e.Name()] = d
			}
		}
	}
	if len(onDisk) > 0 && !pyEqual(onDisk, sourcesOrEmpty(sources)) {
		changed := map[string]bool{}
		for k, v := range onDisk {
			if w, has := sources[k]; !has || !pyEqual(v, w) {
				changed[k] = true
			}
		}
		for k := range sources {
			if _, has := onDisk[k]; !has {
				changed[k] = true
			}
		}
		names := make([]string, 0, len(changed))
		for k := range changed {
			names = append(names, k)
		}
		sort.Strings(names)
		return nil, newErr("bundle_stale", "policies.json does not match the .cedar sources ("+strings.Join(names, ", ")+
			"); run `smartdelegate bundle compile` from the Rust port")
	}
	for _, pid := range sortedKeys(compiled) {
		p, uerr := NewPolicy(pid, compiled[pid])
		if uerr != nil {
			return nil, newErr("policy_parse", "policies.json: "+pid+": "+uerr.Error())
		}
		b.Policies[pid] = p
	}

	b.store, _ = NewStore(nil)
	if p := filepath.Join(dir, "entities.json"); exists(p) {
		text, err := readText(p)
		if err != nil {
			return nil, err
		}
		if err := b.loadEntities(text); err != nil {
			return nil, newErr("entities_parse", err.Error())
		}
	}
	if p := filepath.Join(dir, "catalog.json"); exists(p) {
		text, err := readText(p)
		if err != nil {
			return nil, err
		}
		if err := b.loadCatalog(text); err != nil {
			return nil, newErr("catalog_parse", err.Error())
		}
	}
	if p := filepath.Join(dir, "roles.json"); exists(p) {
		text, err := readText(p)
		if err != nil {
			return nil, err
		}
		if err := b.loadRoles(text); err != nil {
			return nil, newErr("roles_parse", "roles.json: "+err.Error())
		}
	}
	return b, nil
}

func sourcesOrEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func (b *Bundle) loadEntities(text string) error {
	parsed, err := ParseJSON([]byte(text))
	if err != nil {
		return err
	}
	list, ok := parsed.([]any)
	if !ok {
		return errors.New("expected a list of entities")
	}
	for _, e := range list {
		if _, isObject := e.(map[string]any); !isObject {
			return errors.New("expected a list of entities")
		}
	}
	if b.store, err = NewStore(list); err != nil {
		return err
	}
	for _, e := range list {
		m := e.(map[string]any)
		uid, err := storeUID(m["uid"])
		if err != nil {
			return err
		}
		var attrs any = map[string]any{}
		if truthy(m["attrs"]) {
			attrs = m["attrs"]
		}
		b.attrs[uid.Type+"::"+uid.ID] = attrs
	}
	return nil
}

func (b *Bundle) loadCatalog(text string) error {
	parsed, err := ParseJSON([]byte(text))
	if err != nil {
		return err
	}
	cat, ok := parsed.(map[string]any)
	if !ok {
		return errors.New("catalog.json must be an object")
	}
	object := func(v any, what string) (map[string]any, error) {
		if !truthy(v) {
			return nil, nil
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", what)
		}
		return m, nil
	}
	resources, err := object(cat["resources"], "resources")
	if err != nil {
		return err
	}
	for _, path := range sortedKeys(resources) {
		rdef, ok := resources[path].(map[string]any)
		if !ok {
			return fmt.Errorf("%s: must be an object", path)
		}
		if !validType(rdef["entity_type"]) {
			return fmt.Errorf("%s: entity_type is missing or malformed", path)
		}
		def := &resourceDef{entityType: rdef["entity_type"].(string), fields: map[string]*fieldDef{}}
		fields, err := object(rdef["fields"], path+".fields")
		if err != nil {
			return err
		}
		for _, name := range sortedKeys(fields) {
			fdef, ok := fields[name].(map[string]any)
			if !ok {
				return fmt.Errorf("%s.%s: must be an object", path, name)
			}
			f := &fieldDef{labels: []any{}}
			switch mask := fdef["mask"].(type) {
			case nil:
			case string:
				if mask != "drop" && mask != "redact" {
					return fmt.Errorf("%s.%s: mask must be 'drop' or 'redact'", path, name)
				}
				f.mask = mask
			default:
				return fmt.Errorf("%s.%s: mask must be 'drop' or 'redact'", path, name)
			}
			if labels := fdef["labels"]; truthy(labels) {
				switch l := labels.(type) {
				case []any:
					f.labels = l
				case string: // the reference reads a bare string as its characters
					for _, r := range l {
						f.labels = append(f.labels, string(r))
					}
				case map[string]any:
					for _, k := range sortedKeys(l) {
						f.labels = append(f.labels, k)
					}
				default:
					return fmt.Errorf("%s.%s: labels must be a list", path, name)
				}
			}
			def.fields[name] = f
		}
		b.catalog[path] = def
	}
	return nil
}

func (b *Bundle) loadRoles(text string) error {
	parsed, err := ParseJSON([]byte(text))
	if err != nil {
		return err
	}
	doc, _ := parsed.(map[string]any)
	roles, ok := doc["roles"].(map[string]any)
	if !ok {
		return errors.New(`expected {"roles": {...}}`)
	}
	for _, name := range sortedKeys(roles) {
		r, err := newRole(name, roles[name])
		if err != nil {
			return err
		}
		b.Roles[name] = r
	}
	return nil
}

// Role is a role a human holds and can lend to an agent for one task.
type Role struct {
	Name     string
	Members  []Entity       // entities whose members hold the role
	Cap      *Cap           // the ceiling: the most a token issued under this role can carry
	MaxTTL   int64          // 0: no limit of its own
	Tasks    []string       // nil: any task; else the token must name a task matching one pattern
	Agents   []string       // nil: any agent; else only these agents may be started in this role
	Bindings map[string]any // free-form, for bridges; ignored by the engine
}

func patternList(v any, what string) ([]string, error) {
	bad := fmt.Errorf("%s must be a non-empty list of names, each with at most one trailing *", what)
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return nil, bad
	}
	out := make([]string, len(list))
	for i, x := range list {
		s, ok := x.(string)
		if !ok || s == "" || strings.Contains(s[:len(s)-1], "*") {
			return nil, bad
		}
		out[i] = s
	}
	return out, nil
}

func newRole(name string, v any) (*Role, error) {
	m, ok := v.(map[string]any)
	if name == "" || !ok {
		return nil, fmt.Errorf("role '%s' must be an object", name)
	}
	var unknown []string
	for k := range m {
		switch k {
		case "description", "members", "cap", "max_ttl", "tasks", "agents", "bindings":
		default:
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		// a misspelt key must not silently loosen a role
		sort.Strings(unknown)
		return nil, fmt.Errorf("role '%s': unknown field(s): %s", name, strings.Join(unknown, ", "))
	}
	r := &Role{Name: name, Bindings: map[string]any{}}
	members, ok := m["members"].([]any)
	if !ok || len(members) == 0 {
		return nil, fmt.Errorf("role '%s': members must be a non-empty list of {type, id}", name)
	}
	for _, x := range members {
		mm, ok := x.(map[string]any)
		id, okID := mm["id"].(string)
		if !ok || !validType(mm["type"]) || !okID {
			return nil, fmt.Errorf("role '%s': each member must be {type, id}", name)
		}
		r.Members = append(r.Members, Entity{mm["type"].(string), id})
	}
	rawCap, has := m["cap"]
	if !has {
		return nil, fmt.Errorf("role '%s': cap is required", name)
	}
	c, cerr := capFromJSON(rawCap)
	if cerr == nil {
		cerr = c.validate()
	}
	if cerr != nil {
		return nil, errors.New(cerr.Message)
	}
	r.Cap = c
	if t, has := m["max_ttl"]; has {
		n, ok := t.(int64)
		if !ok || n <= 0 {
			return nil, fmt.Errorf("role '%s': max_ttl must be a positive integer", name)
		}
		r.MaxTTL = n
	}
	var err error
	if t, has := m["tasks"]; has {
		if r.Tasks, err = patternList(t, "role '"+name+"': tasks"); err != nil {
			return nil, err
		}
	}
	if a, has := m["agents"]; has {
		if r.Agents, err = patternList(a, "role '"+name+"': agents"); err != nil {
			return nil, err
		}
	}
	if raw, has := m["bindings"]; has {
		bm, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("role '%s': bindings must be an object", name)
		}
		r.Bindings = bm
	}
	return r, nil
}
