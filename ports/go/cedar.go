package smartdelegate

// Evaluator for Cedar's JSON policy form (the portable subset).
//
// What it must do is fixed by spec/conformance/eval/cases.json, whose expected
// answers come from the real Cedar engine. spec/POLICY_SUBSET.md lists what is
// in the subset; anything outside it is refused when the bundle loads.
//
// A Cedar value here is one of: bool, int64 (long), string, Entity, *Set,
// map[string]any (record).

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var typeRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$`)

// Entity is an entity reference: Type::"ID".
type Entity struct {
	Type string
	ID   string
}

func (e Entity) String() string { return e.Type + `::"` + e.ID + `"` }

// Set is a Cedar set: unordered, no duplicates, any element types.
type Set struct {
	items map[string]any // identity key -> value
}

func newSet(values []any) *Set {
	s := &Set{items: make(map[string]any, len(values))}
	for _, v := range values {
		s.items[valueKey(v)] = v
	}
	return s
}

// valueKey is an identity for a value; equal values have equal keys.
func valueKey(v any) string {
	var b strings.Builder
	writeKey(&b, v)
	return b.String()
}

func writeKey(b *strings.Builder, v any) {
	str := func(s string) {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
	}
	switch x := v.(type) {
	case bool:
		if x {
			b.WriteString("b1")
		} else {
			b.WriteString("b0")
		}
	case int64:
		b.WriteByte('l')
		b.WriteString(strconv.FormatInt(x, 10))
		b.WriteByte(';')
	case string:
		b.WriteByte('s')
		str(x)
	case Entity:
		b.WriteByte('e')
		str(x.Type)
		str(x.ID)
	case *Set:
		b.WriteByte('S')
		b.WriteString(strconv.Itoa(len(x.items)))
		b.WriteByte(':')
		for _, k := range sortedKeys(x.items) {
			b.WriteString(k)
		}
	case map[string]any:
		b.WriteByte('R')
		b.WriteString(strconv.Itoa(len(x)))
		b.WriteByte(':')
		for _, k := range sortedKeys(x) {
			str(k)
			writeKey(b, x[k])
		}
	default:
		panic(fmt.Sprintf("not a Cedar value: %T", v))
	}
}

func validType(name any) bool {
	s, ok := name.(string)
	return ok && typeRe.MatchString(s) // a full match: no trailing newline
}

// fromJSON turns JSON into a Cedar value, for entity attributes, context and
// literals. Lists are sets; {"__entity": {type, id}} is an entity reference.
// Floats, nulls and integers outside 64 bits are not Cedar values.
func fromJSON(v any) (any, error) {
	switch x := v.(type) {
	case bool, string, int64:
		return x, nil
	case *big.Int:
		return nil, errors.New("integer does not fit in 64 bits")
	case float64:
		return nil, errors.New("floating-point numbers are not Cedar values")
	case nil:
		return nil, errors.New("null is not a Cedar value")
	case []any:
		vals := make([]any, len(x))
		for i, el := range x {
			c, err := fromJSON(el)
			if err != nil {
				return nil, err
			}
			vals[i] = c
		}
		return newSet(vals), nil
	case map[string]any:
		if e, ok := x["__entity"]; ok {
			em, isMap := e.(map[string]any)
			if len(x) != 1 || !isMap || !validType(em["type"]) {
				return nil, errors.New("malformed __entity reference")
			}
			id, ok := em["id"].(string)
			if !ok {
				return nil, errors.New("malformed __entity reference")
			}
			return Entity{em["type"].(string), id}, nil
		}
		if _, ok := x["__extn"]; ok {
			return nil, errors.New("extension values (decimal, ip, datetime) are outside the portable subset")
		}
		out := make(map[string]any, len(x))
		for k, el := range x {
			c, err := fromJSON(el)
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	}
	return nil, fmt.Errorf("not a JSON value: %T", v)
}

// Store holds entities: attributes and transitive ancestors.
type Store struct {
	attrs     map[Entity]map[string]any
	parents   map[Entity][]Entity
	ancestors map[Entity]map[Entity]bool
}

// NewStore builds a store from the entities.json form: a list of
// {"uid": {type, id}, "attrs": {...}, "parents": [{type, id}]}.
func NewStore(entities []any) (*Store, error) {
	s := &Store{attrs: map[Entity]map[string]any{}, parents: map[Entity][]Entity{}, ancestors: map[Entity]map[Entity]bool{}}
	for _, e := range entities {
		if err := s.add(e); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func storeUID(u any) (Entity, error) {
	if m, ok := u.(map[string]any); ok {
		if inner, has := m["__entity"]; has {
			u = inner
		}
	}
	m, ok := u.(map[string]any)
	if ok && validType(m["type"]) {
		if id, isStr := m["id"].(string); isStr {
			return Entity{m["type"].(string), id}, nil
		}
	}
	return Entity{}, fmt.Errorf("malformed entity uid: %s", Canon(u))
}

func (s *Store) add(e any) error {
	m, ok := e.(map[string]any)
	if !ok {
		return errors.New("an entity must be an object")
	}
	uid, err := storeUID(m["uid"])
	if err != nil {
		return err
	}
	if _, dup := s.attrs[uid]; dup {
		return fmt.Errorf("duplicate entity %s", uid)
	}
	attrs := map[string]any{}
	if raw := m["attrs"]; truthy(raw) {
		am, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: attrs must be an object", uid)
		}
		for k, v := range am {
			c, err := fromJSON(v)
			if err != nil {
				return err
			}
			attrs[k] = c
		}
	}
	var parents []Entity
	if raw := m["parents"]; truthy(raw) {
		list, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("%s: parents must be a list", uid)
		}
		for _, p := range list {
			pu, err := storeUID(p)
			if err != nil {
				return err
			}
			parents = append(parents, pu)
		}
	}
	s.attrs[uid] = attrs
	s.parents[uid] = parents
	s.ancestors = map[Entity]map[Entity]bool{}
	return nil
}

func (s *Store) clone() *Store {
	c := &Store{attrs: make(map[Entity]map[string]any, len(s.attrs)+8), parents: make(map[Entity][]Entity, len(s.parents)+8),
		ancestors: map[Entity]map[Entity]bool{}}
	for k, v := range s.attrs {
		c.attrs[k] = v
	}
	for k, v := range s.parents {
		c.parents[k] = v
	}
	return c
}

// overlay returns a store with request-scoped entities added. The base is not changed.
func (s *Store) overlay(extra []any) (*Store, error) {
	c := s.clone()
	for _, e := range extra {
		if err := c.add(e); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// withParents returns a store in which uid has exactly these parents (and its
// stored attributes, if any). Used for live group membership carried by a token.
func (s *Store) withParents(uid Entity, parents []Entity) *Store {
	c := s.clone()
	if _, ok := c.attrs[uid]; !ok {
		c.attrs[uid] = map[string]any{}
	}
	c.parents[uid] = append([]Entity(nil), parents...)
	return c
}

func (s *Store) has(uid Entity) bool {
	_, ok := s.attrs[uid]
	return ok
}

func (s *Store) ancestorsOf(uid Entity) map[Entity]bool {
	if got, ok := s.ancestors[uid]; ok {
		return got
	}
	seen := map[Entity]bool{}
	stack := append([]Entity(nil), s.parents[uid]...)
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !seen[p] {
			seen[p] = true
			stack = append(stack, s.parents[p]...)
		}
	}
	s.ancestors[uid] = seen
	return seen
}

func (s *Store) isIn(child, ancestor Entity) bool {
	return child == ancestor || s.ancestorsOf(child)[ancestor]
}

// ---- loading: reject anything outside the subset -----------------------------

// Unsupported means the policy uses Cedar that is outside the portable subset
// (or is not well-formed policy JSON).
type Unsupported struct{ Message string }

func (u *Unsupported) Error() string { return u.Message }

func unsupported(format string, a ...any) error {
	return &Unsupported{fmt.Sprintf(format, a...)}
}

var binaryOps = map[string]bool{"==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true, "&&": true, "||": true,
	"+": true, "-": true, "*": true, "in": true, "contains": true, "containsAll": true, "containsAny": true}
var unaryOps = map[string]bool{"!": true, "neg": true, "isEmpty": true}

func entityLit(e any) (Entity, error) {
	if m, ok := e.(map[string]any); ok {
		if inner, has := m["__entity"]; has {
			e = inner
		}
	}
	m, ok := e.(map[string]any)
	if ok && validType(m["type"]) {
		if id, isStr := m["id"].(string); isStr {
			return Entity{m["type"].(string), id}, nil
		}
	}
	return Entity{}, unsupported("malformed entity in policy scope")
}

// listOf reads a JSON list; nothing else passes for one.
func listOf(v any) ([]any, bool) {
	x, ok := v.([]any)
	return x, ok
}

func single(e any) (string, any, bool) {
	m, ok := e.(map[string]any)
	if !ok || len(m) != 1 {
		return "", nil, false
	}
	for k, v := range m {
		return k, v, true
	}
	return "", nil, false
}

func checkExpr(e any, depth int) error {
	if depth > maxDepth {
		return unsupported("expression is nested too deeply")
	}
	op, arg, ok := single(e)
	if !ok {
		return unsupported("malformed expression")
	}
	sub := func(key string) error {
		m, ok := arg.(map[string]any)
		if !ok {
			return unsupported("malformed policy JSON (`%s` needs an object)", op)
		}
		x, has := m[key]
		if !has {
			return unsupported("malformed policy JSON (`%s` has no `%s`)", op, key)
		}
		return checkExpr(x, depth+1)
	}
	switch {
	case op == "Value":
		if _, err := fromJSON(arg); err != nil {
			return unsupported("%s", err.Error())
		}
	case op == "Var":
		s, _ := arg.(string)
		if s != "principal" && s != "action" && s != "resource" && s != "context" {
			return unsupported("unknown variable")
		}
	case binaryOps[op]:
		if err := sub("left"); err != nil {
			return err
		}
		return sub("right")
	case unaryOps[op]:
		return sub("arg")
	case op == "." || op == "has":
		if err := sub("left"); err != nil {
			return err
		}
		if _, ok := arg.(map[string]any)["attr"].(string); !ok {
			return unsupported("attribute name must be a string")
		}
	case op == "is":
		if err := sub("left"); err != nil {
			return err
		}
		m := arg.(map[string]any)
		if !validType(m["entity_type"]) {
			return unsupported("malformed entity type in `is`")
		}
		if _, has := m["in"]; has {
			return sub("in")
		}
	case op == "like":
		if err := sub("left"); err != nil {
			return err
		}
		pattern, ok := listOf(arg.(map[string]any)["pattern"])
		if !ok {
			return unsupported("malformed like pattern")
		}
		for _, part := range pattern {
			if s, isStr := part.(string); isStr && s == "Wildcard" {
				continue
			}
			pm, isMap := part.(map[string]any)
			if !isMap {
				return unsupported("malformed like pattern")
			}
			if _, isStr := pm["Literal"].(string); !isStr {
				return unsupported("malformed like pattern")
			}
		}
	case op == "if-then-else":
		for _, k := range []string{"if", "then", "else"} {
			if err := sub(k); err != nil {
				return err
			}
		}
	case op == "Set":
		list, ok := listOf(arg)
		if !ok {
			return unsupported("malformed policy JSON (Set needs a list)")
		}
		for _, x := range list {
			if err := checkExpr(x, depth+1); err != nil {
				return err
			}
		}
	case op == "Record":
		m, ok := arg.(map[string]any)
		if !ok {
			return unsupported("malformed policy JSON (Record needs an object)")
		}
		for _, x := range m {
			if err := checkExpr(x, depth+1); err != nil {
				return err
			}
		}
	default:
		return unsupported("`%s` is outside the portable Cedar subset", op)
	}
	return nil
}

type scope struct {
	op       string // All, ==, in, in-list, is
	entity   Entity
	entities []Entity
	etype    string
	hasIn    bool
}

func checkScope(raw any, what string) (scope, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return scope{}, unsupported("unsupported %s scope", what)
	}
	if _, has := m["slot"]; has {
		return scope{}, unsupported("policy templates are not supported")
	}
	op, _ := m["op"].(string)
	switch {
	case op == "All":
		return scope{op: "All"}, nil
	case op == "==":
		e, err := entityLit(m["entity"])
		return scope{op: "==", entity: e}, err
	case op == "in":
		if list, has := m["entities"]; has {
			if what != "action" {
				return scope{}, unsupported("%s scope cannot use a list", what)
			}
			items, ok := listOf(list)
			if !ok {
				return scope{}, unsupported("malformed policy JSON (entities must be a list)")
			}
			sc := scope{op: "in-list"}
			for _, x := range items {
				e, err := entityLit(x)
				if err != nil {
					return scope{}, err
				}
				sc.entities = append(sc.entities, e)
			}
			return sc, nil
		}
		e, err := entityLit(m["entity"])
		return scope{op: "in", entity: e}, err
	case op == "is" && what != "action":
		if !validType(m["entity_type"]) {
			return scope{}, unsupported("malformed entity type in scope")
		}
		sc := scope{op: "is", etype: m["entity_type"].(string)}
		if in, has := m["in"]; has {
			im, ok := in.(map[string]any)
			if !ok {
				return scope{}, unsupported("malformed policy JSON (scope `in` needs an object)")
			}
			e, err := entityLit(im["entity"])
			if err != nil {
				return scope{}, err
			}
			sc.hasIn, sc.entity = true, e
		}
		return sc, nil
	}
	return scope{}, unsupported("unsupported %s scope", what)
}

type condition struct {
	when bool
	body any
}

// Policy is one compiled policy, checked to be inside the subset.
type Policy struct {
	ID          string
	Permit      bool
	Annotations map[string]any

	principal, action, resource scope
	conditions                  []condition
}

// NewPolicy checks one entry of policies.json. The error is *Unsupported.
func NewPolicy(id string, est any) (*Policy, error) {
	m, ok := est.(map[string]any)
	if !ok {
		return nil, unsupported("malformed policy JSON (a policy must be an object)")
	}
	effect, _ := m["effect"].(string)
	if effect != "permit" && effect != "forbid" {
		return nil, unsupported("effect must be permit or forbid")
	}
	p := &Policy{ID: id, Permit: effect == "permit", Annotations: map[string]any{}}
	var err error
	if p.principal, err = checkScope(m["principal"], "principal"); err != nil {
		return nil, err
	}
	if p.action, err = checkScope(m["action"], "action"); err != nil {
		return nil, err
	}
	if p.resource, err = checkScope(m["resource"], "resource"); err != nil {
		return nil, err
	}
	if raw, has := m["conditions"]; has {
		list, ok := listOf(raw)
		if !ok {
			return nil, unsupported("malformed policy JSON (conditions must be a list)")
		}
		for _, c := range list {
			cm, ok := c.(map[string]any)
			if !ok {
				return nil, unsupported("malformed policy JSON (a condition must be an object)")
			}
			kind, _ := cm["kind"].(string)
			if kind != "when" && kind != "unless" {
				return nil, unsupported("condition must be when or unless")
			}
			if err := checkExpr(cm["body"], 0); err != nil {
				return nil, err
			}
			p.conditions = append(p.conditions, condition{when: kind == "when", body: cm["body"]})
		}
	}
	if raw := m["annotations"]; truthy(raw) {
		am, ok := raw.(map[string]any)
		if !ok {
			return nil, unsupported("malformed policy JSON (annotations must be an object)")
		}
		for k, v := range am {
			if v == nil {
				v = ""
			}
			p.Annotations[k] = v
		}
	}
	return p, nil
}

// ---- evaluation ----------------------------------------------------------------

// EvalError means a policy condition could not be evaluated. The policy is skipped.
type EvalError struct{ Message string }

func (e *EvalError) Error() string { return e.Message }

func evalErr(format string, a ...any) error { return &EvalError{fmt.Sprintf(format, a...)} }

// Env is one authorization request.
type Env struct {
	Principal, Action, Resource Entity
	Context                     map[string]any // a Cedar record
	Store                       *Store
}

func asBool(v any, what string) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, evalErr("%s must be a boolean", what)
	}
	return b, nil
}

func asLong(v any, what string) (int64, error) {
	n, ok := v.(int64)
	if !ok {
		return 0, evalErr("%s must be a long", what)
	}
	return n, nil
}

func asSet(v any, what string) (*Set, error) {
	s, ok := v.(*Set)
	if !ok {
		return nil, evalErr("%s must be a set", what)
	}
	return s, nil
}

var errOverflow = &EvalError{"integer overflow"}

func addChecked(x, y int64) (int64, error) {
	s := x + y
	if (s > x) != (y > 0) {
		return 0, errOverflow
	}
	return s, nil
}

func subChecked(x, y int64) (int64, error) {
	d := x - y
	if (d < x) != (y > 0) {
		return 0, errOverflow
	}
	return d, nil
}

func mulChecked(x, y int64) (int64, error) {
	if x == 0 || y == 0 {
		return 0, nil
	}
	p := x * y
	if (x == -1 && y == math.MinInt64) || (y == -1 && x == math.MinInt64) || p/y != x {
		return 0, errOverflow
	}
	return p, nil
}

// like is the classic wildcard match with backtracking to the last star.
// Each literal in the pattern is one character.
func like(s []rune, pattern []any) bool {
	wild := func(j int) bool {
		w, ok := pattern[j].(string)
		return ok && w == "Wildcard"
	}
	i, j := 0, 0
	star, mark := -1, -1
	for i < len(s) {
		switch {
		case j < len(pattern) && !wild(j) && pattern[j].(map[string]any)["Literal"].(string) == string(s[i]):
			i++
			j++
		case j < len(pattern) && wild(j):
			star, mark = j, i
			j++
		case star != -1:
			j = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for j < len(pattern) && wild(j) {
		j++
	}
	return j == len(pattern)
}

func evaluate(e any, env *Env) (any, error) {
	op, raw, _ := single(e)
	a, _ := raw.(map[string]any)
	switch op {
	case "Value":
		v, err := fromJSON(raw)
		if err != nil {
			return nil, evalErr("%s", err.Error())
		}
		return v, nil
	case "Var":
		switch raw {
		case "principal":
			return env.Principal, nil
		case "action":
			return env.Action, nil
		case "resource":
			return env.Resource, nil
		}
		return env.Context, nil
	case "&&", "||":
		left, err := evaluate(a["left"], env)
		if err != nil {
			return nil, err
		}
		l, err := asBool(left, "left of "+op)
		if err != nil {
			return nil, err
		}
		if l == (op == "||") {
			return l, nil
		}
		right, err := evaluate(a["right"], env)
		if err != nil {
			return nil, err
		}
		return asBool(right, "right of "+op)
	case "if-then-else":
		c, err := evaluate(a["if"], env)
		if err != nil {
			return nil, err
		}
		b, err := asBool(c, "if condition")
		if err != nil {
			return nil, err
		}
		if b {
			return evaluate(a["then"], env)
		}
		return evaluate(a["else"], env)
	case "!", "neg", "isEmpty":
		v, err := evaluate(a["arg"], env)
		if err != nil {
			return nil, err
		}
		switch op {
		case "!":
			b, err := asBool(v, "operand of !")
			return !b, err
		case "neg":
			n, err := asLong(v, "operand of -")
			if err != nil {
				return nil, err
			}
			return subChecked(0, n)
		}
		s, err := asSet(v, "isEmpty receiver")
		if err != nil {
			return nil, err
		}
		return len(s.items) == 0, nil
	case ".", "has":
		left, err := evaluate(a["left"], env)
		if err != nil {
			return nil, err
		}
		attr := a["attr"].(string)
		var rec map[string]any
		switch x := left.(type) {
		case Entity:
			stored, ok := env.Store.attrs[x]
			if !ok && op == "." {
				return nil, evalErr("entity %s does not exist", x)
			}
			rec = stored
		case map[string]any:
			rec = x
		default:
			return nil, evalErr("`%s` needs an entity or a record", op)
		}
		v, ok := rec[attr]
		if op == "has" {
			return ok, nil
		}
		if !ok {
			return nil, evalErr("no attribute `%s`", attr)
		}
		return v, nil
	case "is":
		left, err := evaluate(a["left"], env)
		if err != nil {
			return nil, err
		}
		ent, ok := left.(Entity)
		if !ok {
			return nil, evalErr("`is` needs an entity")
		}
		if ent.Type != a["entity_type"].(string) {
			return false, nil
		}
		if in, has := a["in"]; has {
			right, err := evaluate(in, env)
			if err != nil {
				return nil, err
			}
			return entityIn(ent, right, env)
		}
		return true, nil
	case "like":
		left, err := evaluate(a["left"], env)
		if err != nil {
			return nil, err
		}
		s, ok := left.(string)
		if !ok {
			return nil, evalErr("`like` needs a string")
		}
		pattern, _ := listOf(a["pattern"])
		return like([]rune(s), pattern), nil
	case "Set":
		list, _ := raw.([]any)
		vals := make([]any, len(list))
		for i, x := range list {
			v, err := evaluate(x, env)
			if err != nil {
				return nil, err
			}
			vals[i] = v
		}
		return newSet(vals), nil
	case "Record":
		out := make(map[string]any, len(a))
		// in key order, so which error is reported does not depend on map order
		for _, k := range sortedKeys(a) {
			v, err := evaluate(a[k], env)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	}
	if !binaryOps[op] {
		return nil, evalErr("unsupported operator %s", op)
	}
	left, err := evaluate(a["left"], env)
	if err != nil {
		return nil, err
	}
	right, err := evaluate(a["right"], env)
	if err != nil {
		return nil, err
	}
	switch op {
	case "==":
		return valueKey(left) == valueKey(right), nil
	case "!=":
		return valueKey(left) != valueKey(right), nil
	case "<", "<=", ">", ">=", "+", "-", "*":
		x, err := asLong(left, "left of "+op)
		if err != nil {
			return nil, err
		}
		y, err := asLong(right, "right of "+op)
		if err != nil {
			return nil, err
		}
		switch op {
		case "<":
			return x < y, nil
		case "<=":
			return x <= y, nil
		case ">":
			return x > y, nil
		case ">=":
			return x >= y, nil
		case "+":
			return addChecked(x, y)
		case "-":
			return subChecked(x, y)
		}
		return mulChecked(x, y)
	case "in":
		ent, ok := left.(Entity)
		if !ok {
			return nil, evalErr("left of `in` must be an entity")
		}
		return entityIn(ent, right, env)
	case "contains":
		s, err := asSet(left, "contains receiver")
		if err != nil {
			return nil, err
		}
		_, ok := s.items[valueKey(right)]
		return ok, nil
	}
	// containsAll, containsAny
	l, err := asSet(left, op+" receiver")
	if err != nil {
		return nil, err
	}
	r, err := asSet(right, op+" argument")
	if err != nil {
		return nil, err
	}
	all := op == "containsAll"
	for k := range r.items {
		if _, ok := l.items[k]; ok != all {
			return !all, nil
		}
	}
	return all, nil
}

func entityIn(left Entity, right any, env *Env) (any, error) {
	switch x := right.(type) {
	case Entity:
		return env.Store.isIn(left, x), nil
	case *Set:
		found := false
		for _, v := range x.items {
			ent, ok := v.(Entity)
			if !ok {
				return nil, evalErr("right of `in` must be an entity or a set of entities")
			}
			found = found || env.Store.isIn(left, ent)
		}
		return found, nil
	}
	return nil, evalErr("right of `in` must be an entity or a set of entities")
}

func (sc *scope) matches(who Entity, store *Store) bool {
	switch sc.op {
	case "All":
		return true
	case "==":
		return who == sc.entity
	case "in":
		return store.isIn(who, sc.entity)
	case "in-list":
		for _, e := range sc.entities {
			if store.isIn(who, e) {
				return true
			}
		}
		return false
	}
	return who.Type == sc.etype && (!sc.hasIn || store.isIn(who, sc.entity))
}

// applies is true when the policy's scope and every condition hold.
func (p *Policy) applies(env *Env) (bool, error) {
	if !(p.principal.matches(env.Principal, env.Store) && p.action.matches(env.Action, env.Store) && p.resource.matches(env.Resource, env.Store)) {
		return false, nil
	}
	for _, c := range p.conditions {
		v, err := evaluate(c.body, env)
		if err != nil {
			return false, err
		}
		b, err := asBool(v, "condition")
		if err != nil {
			return false, err
		}
		if b != c.when {
			return false, nil
		}
	}
	return true, nil
}

// PolicyError is a policy that was skipped because it could not be evaluated.
type PolicyError struct{ ID, Message string }

// AuthResult is Cedar's answer.
type AuthResult struct {
	Allow   bool
	Reasons []string // the forbids that denied, or the permits that allowed
	Errors  []PolicyError
}

// IsAuthorized is Cedar's authorization: a satisfied forbid denies; otherwise
// a satisfied permit allows; otherwise deny. Policies are visited in id order.
func IsAuthorized(policies map[string]*Policy, env *Env) AuthResult {
	ids := make([]string, 0, len(policies))
	for id := range policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var permits, forbids []string
	var errs []PolicyError
	for _, id := range ids {
		p := policies[id]
		ok, err := p.applies(env)
		switch {
		case err != nil:
			errs = append(errs, PolicyError{id, err.Error()})
		case ok && p.Permit:
			permits = append(permits, id)
		case ok:
			forbids = append(forbids, id)
		}
	}
	if len(forbids) > 0 {
		return AuthResult{Allow: false, Reasons: forbids, Errors: errs}
	}
	if len(permits) > 0 {
		return AuthResult{Allow: true, Reasons: permits, Errors: errs}
	}
	return AuthResult{Allow: false, Errors: errs}
}
