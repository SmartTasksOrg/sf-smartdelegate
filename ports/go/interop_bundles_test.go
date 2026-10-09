package smartdelegate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Bundles of every shape, loaded by this port and by the Python reference:
// both must load the same ones, refuse the others with the same error code,
// and compute the same version. Then a bundle whose annotations (row filter,
// rate limit, approval) and catalog are written in every accepted and
// rejected form, with the same requests sent to both.

func writeBundle(t *testing.T, dir string, files map[string]any) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if content == nil {
			_ = os.RemoveAll(path)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if content == "<directory>" {
			_ = os.RemoveAll(path)
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		var raw []byte
		switch c := content.(type) {
		case string:
			raw = []byte(c)
		case []byte:
			raw = c
		default:
			raw = MarshalJSON(content)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func expr(text string) any {
	v, err := ParseJSON([]byte(text))
	if err != nil {
		panic(err)
	}
	return v
}

var (
	scopeAll  = map[string]any{"op": "All"}
	exprTrue  = expr(`{"Value": true}`)
	entityRef = expr(`{"Value": {"__entity": {"type": "User", "id": "u"}}}`)
)

func policy(change map[string]any) map[string]any {
	p := map[string]any{"effect": "permit", "principal": scopeAll, "action": scopeAll, "resource": scopeAll, "conditions": []any{}}
	for k, v := range change {
		if v == "<absent>" {
			delete(p, k)
		} else {
			p[k] = v
		}
	}
	return p
}

func when(body any) map[string]any {
	return policy(map[string]any{"conditions": []any{map[string]any{"kind": "when", "body": body}}})
}

func baseBundle() map[string]any {
	return map[string]any{
		"policies.json": map[string]any{"format": "cedar-json/1", "sources": map[string]any{}, "policies": map[string]any{"p": policy(nil)}},
		"entities.json": expr(`[{"uid": {"type": "User", "id": "u"}, "attrs": {"n": 1}, "parents": [{"type": "Group", "id": "g"}]},
			{"uid": {"type": "Group", "id": "g"}}, {"uid": {"type": "Agent", "id": "a"}, "attrs": {}, "parents": []}]`),
		"catalog.json": expr(`{"resources": {"t.item": {"entity_type": "Item", "fields": {"a": {}, "b": {"labels": ["x"], "mask": "redact"}}}}}`),
		"roles.json":   expr(`{"roles": {"r": {"members": [{"type": "Group", "id": "g"}], "cap": {"actions": ["*"], "resources": ["*"]}}}}`),
	}
}

type bundleShape struct {
	name   string
	files  map[string]any
	config map[string]any
}

func bundleShapes() []bundleShape {
	var shapes []bundleShape
	add := func(name string, files map[string]any) {
		shapes = append(shapes, bundleShape{name: name, files: files})
	}
	policies := func(name string, set map[string]any) {
		add("policies: "+name, map[string]any{"policies.json": map[string]any{"policies": set}})
	}
	one := func(name string, p any) { policies(name, map[string]any{"p": p}) }
	cond := func(name string, body any) { one("expression: "+name, when(body)) }
	entities := func(name, text string) { add("entities: "+name, map[string]any{"entities.json": text}) }
	catalog := func(name, text string) { add("catalog: "+name, map[string]any{"catalog.json": text}) }
	roles := func(name, text string) { add("roles: "+name, map[string]any{"roles.json": text}) }
	role := func(name, body string) { roles(name, `{"roles": {"r": `+body+`}}`) }

	add("the base bundle", nil)
	add("only policies.json", map[string]any{"entities.json": nil, "catalog.json": nil, "roles.json": nil})
	add("CRLF line endings", map[string]any{"entities.json": "[\r\n  {\"uid\": {\"type\": \"User\", \"id\": \"u\"}}\r\n]\r\n", "catalog.json": "{\r\n}\r\n", "roles.json": "{\"roles\":\r\n{}}"})
	add("LF line endings, same content", map[string]any{"entities.json": "[\n  {\"uid\": {\"type\": \"User\", \"id\": \"u\"}}\n]\n", "catalog.json": "{\n}\n", "roles.json": "{\"roles\":\n{}}"})
	add("a lone CR is content", map[string]any{"catalog.json": "{\r}\r"})
	add("non-ASCII content", map[string]any{"entities.json": `[{"uid": {"type": "User", "id": "` + "\u00e9\U0001F600" + `"}, "attrs": {"` + "\u00fc" + `": "` + "\u2028" + `"}}]`})
	add("no policies.json", map[string]any{"policies.json": nil})
	add("policies.json is a directory", map[string]any{"policies.json": "<directory>"})
	add("entities.json is a directory", map[string]any{"entities.json": "<directory>"})
	add("a tests directory and other files are not part of the version", map[string]any{"tests/x.json": "{}", "README.md": "hello", "bundle.sig.json": "junk"})
	add("policies.json is not JSON", map[string]any{"policies.json": "{"})
	add("policies.json is a list", map[string]any{"policies.json": "[]"})
	add("policies is a list", map[string]any{"policies.json": `{"policies": []}`})
	add("no policies key", map[string]any{"policies.json": `{"sources": {}}`})
	add("no policies at all", map[string]any{"policies.json": `{"policies": {}}`})
	add("sources is not an object", map[string]any{"policies.json": map[string]any{"sources": []any{1}, "policies": map[string]any{}}})
	add("a .cedar source that was not compiled", map[string]any{"policies/a.cedar": "permit(principal, action, resource);\n"})
	add("a .cedar source with the recorded hash", map[string]any{"policies/a.cedar": "permit(principal, action, resource);\r\n",
		"policies.json": map[string]any{"sources": map[string]any{"policies/a.cedar": sha256Hex([]byte("permit(principal, action, resource);\n"))}, "policies": map[string]any{}}})
	add("a recorded source that is gone, another present", map[string]any{"policies/b.cedar": "x",
		"policies.json": map[string]any{"sources": map[string]any{"policies/a.cedar": "00", "policies/b.cedar": sha256Hex([]byte("x"))}, "policies": map[string]any{}}})
	add("recorded sources but no .cedar files", map[string]any{"policies.json": map[string]any{"sources": map[string]any{"policies/a.cedar": "00"}, "policies": map[string]any{}}})
	add("files in policies/ that are not .cedar", map[string]any{"policies/notes.txt": "x", "policies/a.cedar.bak": "y"})

	one("a number", 5)
	one("a list", []any{})
	one("effect allow", policy(map[string]any{"effect": "allow"}))
	one("effect missing", policy(map[string]any{"effect": "<absent>"}))
	one("forbid", policy(map[string]any{"effect": "forbid"}))
	one("conditions missing", policy(map[string]any{"conditions": "<absent>"}))
	one("conditions null", policy(map[string]any{"conditions": nil}))
	one("conditions an object", policy(map[string]any{"conditions": map[string]any{}}))
	one("condition kind", policy(map[string]any{"conditions": []any{map[string]any{"kind": "if", "body": exprTrue}}}))
	one("condition without body", policy(map[string]any{"conditions": []any{map[string]any{"kind": "when"}}}))
	one("condition is a string", policy(map[string]any{"conditions": []any{"when"}}))
	one("annotations with null and empty values", policy(map[string]any{"annotations": map[string]any{"id": "p", "x": nil, "y": ""}}))
	one("annotations null", policy(map[string]any{"annotations": nil}))
	one("annotations empty list", policy(map[string]any{"annotations": []any{}}))
	for _, what := range []string{"principal", "action", "resource"} {
		scope := func(name string, s any) { one(what+" scope: "+name, policy(map[string]any{what: s})) }
		scope("missing", "<absent>")
		scope("a string", "All")
		scope("no op", map[string]any{})
		scope("unknown op", expr(`{"op": "!="}`))
		scope("==", expr(`{"op": "==", "entity": {"type": "NS::T", "id": "x"}}`))
		scope("== with __entity", expr(`{"op": "==", "entity": {"__entity": {"type": "T", "id": "x"}}}`))
		scope("== without entity", expr(`{"op": "=="}`))
		scope("== bad type", expr(`{"op": "==", "entity": {"type": "bad type", "id": "x"}}`))
		scope("== id a number", expr(`{"op": "==", "entity": {"type": "T", "id": 5}}`))
		scope("== slot", expr(`{"op": "==", "slot": "?principal"}`))
		scope("All with slot", expr(`{"op": "All", "slot": "?principal"}`))
		scope("in", expr(`{"op": "in", "entity": {"type": "T", "id": "x"}}`))
		scope("in a list", expr(`{"op": "in", "entities": [{"type": "T", "id": "x"}, {"type": "T", "id": "y"}]}`))
		scope("in an empty list", expr(`{"op": "in", "entities": []}`))
		scope("in a list with a bad entity", expr(`{"op": "in", "entities": [{"type": "T"}]}`))
		scope("in entities that is no list", expr(`{"op": "in", "entities": {"type": "T", "id": "x"}}`))
		scope("is", expr(`{"op": "is", "entity_type": "NS::T"}`))
		scope("is without a type", expr(`{"op": "is"}`))
		scope("is bad type", expr(`{"op": "is", "entity_type": "1T"}`))
		scope("is in", expr(`{"op": "is", "entity_type": "T", "in": {"entity": {"type": "G", "id": "g"}}}`))
		scope("is in without entity", expr(`{"op": "is", "entity_type": "T", "in": {}}`))
		scope("is in a string", expr(`{"op": "is", "entity_type": "T", "in": "G"}`))
		scope("is in slot", expr(`{"op": "is", "entity_type": "T", "in": {"slot": "?resource"}}`))
	}
	cond("true", exprTrue)
	cond("not an object", "true")
	cond("two operators", expr(`{"Value": true, "Var": "context"}`))
	cond("empty object", expr(`{}`))
	cond("unknown operator", expr(`{"xor": {"left": {"Value": true}, "right": {"Value": true}}}`))
	for _, op := range []string{"ip", "decimal", "datetime", "duration", "isLoopback", "lessThan", "hasTag", "getTag", "isInRange", "offset", "toDate", "unknown", "Slot"} {
		cond("outside the subset: "+op, map[string]any{op: []any{exprTrue}})
	}
	for _, v := range []string{`1`, `-9223372036854775808`, `9223372036854775808`, `1.5`, `null`, `"s"`, `[1, [2]]`, `{"a": {"b": []}}`, `{"__entity": {"type": "T", "id": "x"}}`,
		`{"__entity": {"type": "T"}}`, `{"__entity": {"type": "T", "id": "x"}, "more": 1}`, `{"__extn": {"fn": "decimal", "arg": "1.5"}}`, `[{"a": 1.0}]`, `{"a": null}`} {
		cond("Value "+v, map[string]any{"Value": expr(v)})
	}
	for _, v := range []string{`"principal"`, `"action"`, `"resource"`, `"context"`, `"Principal"`, `"env"`, `5`, `null`, `["context"]`} {
		cond("Var "+v, map[string]any{"Var": expr(v)})
	}
	for op := range binaryOps {
		cond(op, map[string]any{op: map[string]any{"left": entityRef, "right": entityRef}})
		cond(op+" without right", map[string]any{op: map[string]any{"left": entityRef}})
		cond(op+" without left", map[string]any{op: map[string]any{"right": entityRef}})
		cond(op+" with a list", map[string]any{op: []any{entityRef, entityRef}})
		cond(op+" with a bad operand", map[string]any{op: map[string]any{"left": entityRef, "right": expr(`{"Value": null}`)}})
	}
	for op := range unaryOps {
		cond(op, map[string]any{op: map[string]any{"arg": exprTrue}})
		cond(op+" without arg", map[string]any{op: map[string]any{}})
		cond(op+" with a string", map[string]any{op: "x"})
	}
	for _, op := range []string{".", "has"} {
		cond(op, map[string]any{op: map[string]any{"left": entityRef, "attr": "n"}})
		cond(op+" without attr", map[string]any{op: map[string]any{"left": entityRef}})
		cond(op+" attr a number", map[string]any{op: map[string]any{"left": entityRef, "attr": 5}})
		cond(op+" without left", map[string]any{op: map[string]any{"attr": "n"}})
		cond(op+" with a string", map[string]any{op: "n"})
	}
	cond("is", expr(`{"is": {"left": {"Var": "principal"}, "entity_type": "User"}}`))
	cond("is in", expr(`{"is": {"left": {"Var": "principal"}, "entity_type": "User", "in": {"Value": {"__entity": {"type": "Group", "id": "g"}}}}}`))
	cond("is without a type", expr(`{"is": {"left": {"Var": "principal"}}}`))
	cond("is bad type", expr(`{"is": {"left": {"Var": "principal"}, "entity_type": "a b"}}`))
	cond("is in a bad expression", expr(`{"is": {"left": {"Var": "principal"}, "entity_type": "User", "in": {"ip": []}}}`))
	cond("is without left", expr(`{"is": {"entity_type": "User"}}`))
	cond("like", expr(`{"like": {"left": {"Value": "abc"}, "pattern": [{"Literal": "a"}, "Wildcard", {"Literal": "c"}]}}`))
	cond("like empty pattern", expr(`{"like": {"left": {"Value": ""}, "pattern": []}}`))
	cond("like without pattern", expr(`{"like": {"left": {"Value": "abc"}}}`))
	cond("like pattern a string part", expr(`{"like": {"left": {"Value": "abc"}, "pattern": ["a"]}}`))
	cond("like pattern literal a number", expr(`{"like": {"left": {"Value": "abc"}, "pattern": [{"Literal": 5}]}}`))
	cond("like pattern an odd object", expr(`{"like": {"left": {"Value": "abc"}, "pattern": [{"Wildcard": true}]}}`))
	cond("like pattern with extra keys", expr(`{"like": {"left": {"Value": "abc"}, "pattern": [{"Literal": "abc", "x": 1}]}}`))
	cond("like pattern null", expr(`{"like": {"left": {"Value": "abc"}, "pattern": null}}`))
	cond("if-then-else", expr(`{"if-then-else": {"if": {"Value": true}, "then": {"Value": true}, "else": {"Value": false}}}`))
	cond("if-then-else without else", expr(`{"if-then-else": {"if": {"Value": true}, "then": {"Value": true}}}`))
	cond("if-then-else with a bad branch", expr(`{"if-then-else": {"if": {"Value": true}, "then": {"Value": true}, "else": {"ip": []}}}`))
	cond("Set", expr(`{"Set": [{"Value": 1}, {"Set": []}]}`))
	cond("Set of a bad expression", expr(`{"Set": [{"Value": 1.5}]}`))
	cond("Set an object", expr(`{"Set": {"a": {"Value": 1}}}`))
	cond("Set null", expr(`{"Set": null}`))
	cond("Record", expr(`{"Record": {"a": {"Value": 1}, "b": {"Record": {}}}}`))
	cond("Record of a bad expression", expr(`{"Record": {"a": {"Var": "nope"}}}`))
	cond("Record a list", expr(`{"Record": [{"Value": 1}]}`))
	policies("the second one is outside the subset", map[string]any{"a": policy(nil), "b": when(expr(`{"ip": []}`))})

	// shapes the reference used to iterate over without checking (Strictness, spec/PORTING.md)
	one("conditions an empty string", policy(map[string]any{"conditions": ""}))
	one("conditions a string", policy(map[string]any{"conditions": "ab"}))
	one("conditions a non-empty object", policy(map[string]any{"conditions": map[string]any{"a": 1}}))
	one("conditions a number", policy(map[string]any{"conditions": 0}))
	for _, ann := range []any{[]any{1}, "x", 5, true, 0, "", false} {
		one("annotations "+string(MarshalJSON(ann)), policy(map[string]any{"annotations": ann}))
	}
	cond("Set an empty object", expr(`{"Set": {}}`))
	cond("Set an empty string", expr(`{"Set": ""}`))
	cond("Record an empty list", expr(`{"Record": []}`))
	cond("Record an empty string", expr(`{"Record": ""}`))
	cond("like pattern an empty object", expr(`{"like": {"left": {"Value": ""}, "pattern": {}}}`))
	cond("like pattern an empty string", expr(`{"like": {"left": {"Value": ""}, "pattern": ""}}`))
	cond("like pattern the word Wildcard", expr(`{"like": {"left": {"Value": ""}, "pattern": "Wildcard"}}`))
	one("action scope: entities an empty object", policy(map[string]any{"action": expr(`{"op": "in", "entities": {}}`)}))
	one("action scope: entities an empty string", policy(map[string]any{"action": expr(`{"op": "in", "entities": ""}`)}))
	one("resource scope: type with a trailing newline", policy(map[string]any{"resource": expr(`{"op": "is", "entity_type": "Item\n"}`)}))
	cond("is: type with a trailing newline", expr(`{"is": {"left": {"Var": "principal"}, "entity_type": "User\n"}}`))
	cond("Value: entity type with a trailing newline", expr(`{"Value": {"__entity": {"type": "User\n", "id": "u"}}}`))
	for _, e := range []string{`null`, `0`, `false`, `true`, `[null]`, `[[]]`, `[{"uid": {"__entity": {"type": "T", "id": "x"}}, "attrs": {"a": 1}}]`,
		`[{"uid": {"__entity": {"type": "T"}}}]`, `[{"uid": {"type": "T", "id": "x"}}, "x"]`} {
		entities("top level "+e, e)
	}
	notUTF8 := []byte("{\"a\": \"\xff\xfe\"}")
	for _, f := range []string{"policies.json", "entities.json", "catalog.json", "roles.json", "policies/a.cedar"} {
		add("not UTF-8: "+f, map[string]any{f: notUTF8})
	}
	catalog("entity type with a trailing newline", `{"resources": {"t": {"entity_type": "T\n"}}}`)
	role("member type with a trailing newline", `{"members": [{"type": "Group\n", "id": "g"}], "cap": {}}`)

	entities("not JSON", `[`)
	entities("an empty object", `{}`)
	entities("an empty string", `""`)
	entities("an empty list", `[]`)
	entities("an object", `{"uid": {"type": "T", "id": "x"}}`)
	entities("a string", `"entities"`)
	entities("a number", `5`)
	entities("a list of numbers", `[5]`)
	entities("a list of strings", `["x"]`)
	entities("no uid", `[{"attrs": {}}]`)
	entities("uid a string", `[{"uid": "T::x"}]`)
	entities("uid without id", `[{"uid": {"type": "T"}}]`)
	entities("uid id a number", `[{"uid": {"type": "T", "id": 5}}]`)
	entities("uid bad type", `[{"uid": {"type": "bad type", "id": "x"}}]`)
	entities("uid type with a trailing newline", `[{"uid": {"type": "T\n", "id": "x"}}]`)
	entities("uid namespaced, odd id", `[{"uid": {"type": "A::B::C_1", "id": "x y \"z\""}}]`)
	entities("a duplicate", `[{"uid": {"type": "T", "id": "x"}}, {"uid": {"type": "T", "id": "x"}}]`)
	for _, attrs := range []string{`null`, `[]`, `0`, `false`, `""`, `{}`, `"x"`, `[1]`, `5`, `true`, `{"a": 1.5}`, `{"a": null}`, `{"a": {"__extn": {}}}`, `{"a": 9223372036854775808}`,
		`{"a": [1, "x", true, {"b": {"__entity": {"type": "T", "id": "y"}}}]}`, `{"a": {"__entity": {"type": "T"}}}`} {
		entities("attrs "+attrs, `[{"uid": {"type": "T", "id": "x"}, "attrs": `+attrs+`}]`)
	}
	for _, parents := range []string{`null`, `[]`, `0`, `false`, `""`, `{}`, `"abc"`, `[5]`, `5`, `true`, `{"type": "G", "id": "g"}`, `[{"type": "G", "id": "nowhere"}]`,
		`[{"__entity": {"type": "G", "id": "g"}}]`, `[{"type": "G"}]`, `["G::g"]`, `[{"type": "T", "id": "x"}]`} {
		entities("parents "+parents, `[{"uid": {"type": "T", "id": "x"}, "parents": `+parents+`}]`)
	}

	catalog("not JSON", `{"resources"`)
	catalog("a list", `[]`)
	catalog("a string", `"x"`)
	catalog("empty", `{}`)
	for _, r := range []string{`null`, `[]`, `{}`, `0`, `"x"`, `[1]`, `5`, `{"t": 5}`, `{"t": {}}`, `{"t": {"entity_type": "bad type"}}`, `{"t": {"entity_type": 5}}`, `{"t": {"entity_type": "T"}}`,
		`{"": {"entity_type": "A::B"}, "x.y/z": {"entity_type": "T", "fields": null}}`} {
		catalog("resources "+r, `{"resources": `+r+`}`)
	}
	for _, f := range []string{`null`, `[]`, `{}`, `"x"`, `[1]`, `5`, `{"f": 5}`, `{"f": null}`, `{"f": []}`, `{"f": {}}`, `{"f": {"mask": "drop"}}`, `{"f": {"mask": "redact"}}`, `{"f": {"mask": null}}`,
		`{"f": {"mask": "hide"}}`, `{"f": {"mask": 5}}`, `{"f": {"mask": ["drop"]}}`, `{"f": {"mask": ""}}`, `{"f": {"labels": []}}`, `{"f": {"labels": null}}`, `{"f": {"labels": 0}}`,
		`{"f": {"labels": false}}`, `{"f": {"labels": ""}}`, `{"f": {"labels": "ab"}}`, `{"f": {"labels": {"k": 1, "j": 2}}}`, `{"f": {"labels": 5}}`, `{"f": {"labels": true}}`,
		`{"f": {"labels": ["a", 5, ["b"], {"c": true}]}}`, `{"f": {"labels": ["a"], "mask": "drop", "other": 1}}`, `{"a.b": {}, "c[]": {}, "c[].d": {}, "": {}}`} {
		catalog("fields "+f, `{"resources": {"t": {"entity_type": "T", "fields": `+f+`}}}`)
	}

	roles("not JSON", `{"roles"`)
	roles("a list", `[]`)
	roles("roles a list", `{"roles": []}`)
	roles("no roles key", `{"role": {}}`)
	roles("no roles", `{"roles": {}}`)
	roles("an empty name", `{"roles": {"": {"members": [{"type": "Group", "id": "g"}], "cap": {}}}}`)
	roles("extra top-level keys", `{"roles": {}, "version": 1}`)
	members := `"members": [{"type": "Group", "id": "g"}]`
	for _, body := range []string{`5`, `null`, `[]`, `{}`, `{` + members + `}`, `{"cap": {}}`, `{` + members + `, "cap": {}}`, `{` + members + `, "cap": {}, "max_tll": 5}`,
		`{"members": [], "cap": {}}`, `{"members": "g", "cap": {}}`, `{"members": [{"type": "bad type", "id": "g"}], "cap": {}}`, `{"members": [{"type": "Group"}], "cap": {}}`,
		`{"members": ["Group::g"], "cap": {}}`, `{"members": [{"type": "User", "id": "u"}, {"type": "Group", "id": "nowhere"}], "cap": {}}`,
		`{` + members + `, "cap": null}`, `{` + members + `, "cap": []}`, `{` + members + `, "cap": {"acitons": []}}`, `{` + members + `, "cap": {"actions": ["a*b"]}}`,
		`{` + members + `, "cap": {"resources": [""]}}`, `{` + members + `, "cap": {"budget": {"EUR": -1}}}`, `{` + members + `, "cap": {"budget": {"EUR": 1.5}}}`,
		`{` + members + `, "cap": {"actions": ["*"], "resources": ["a/*"], "deny_labels": ["x"], "deny_fields": ["t.f"], "budget": {"EUR": 0}}}`} {
		role("body "+body, body)
	}
	for key, values := range map[string][]string{
		"max_ttl":     {`1`, `0`, `-1`, `true`, `"5"`, `1.5`, `null`, `9223372036854775807`},
		"tasks":       {`["a", "b-*", "*"]`, `[]`, `["a*b"]`, `"x"`, `[""]`, `null`, `[5]`, `["**"]`, `{"a": 1}`},
		"agents":      {`["a"]`, `[]`, `["*a"]`, `"a"`, `null`},
		"bindings":    {`{}`, `{"aws": {"role_arn": "arn"}}`, `[]`, `null`, `"x"`, `5`},
		"description": {`"text"`, `5`, `null`, `[]`},
	} {
		for _, v := range values {
			role(key+" "+v, `{`+members+`, "cap": {}, "`+key+`": `+v+`}`)
		}
	}
	sort.SliceStable(shapes, func(i, j int) bool { return shapes[i].name < shapes[j].name }) // map iteration above is random
	return shapes
}

func TestInteropBundleShapes(t *testing.T) {
	shapes := bundleShapes()

	// signatures
	private, public, _ := Keygen()
	_, otherPublic, _ := Keygen()
	signedDir := t.TempDir()
	writeBundle(t, signedDir, baseBundle())
	if _, err := SignBundle(signedDir, private); err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(filepath.Join(signedDir, "bundle.sig.json"))
	sigDoc := expr(string(sig)).(map[string]any)
	with := func(change map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range sigDoc {
			out[k] = v
		}
		for k, v := range change {
			if v == "<absent>" {
				delete(out, k)
			} else {
				out[k] = v
			}
		}
		return out
	}
	signed := func(name string, sigFile any, key string, more map[string]any) {
		files := map[string]any{"bundle.sig.json": sigFile}
		for k, v := range more {
			files[k] = v
		}
		shapes = append(shapes, bundleShape{name: "signature: " + name, files: files, config: map[string]any{"bundle_public_key": key}})
	}
	signed("valid", sig, public, nil)
	signed("valid, key with surrounding whitespace", sig, " "+public+"\n", nil)
	signed("valid, compact file with extra keys", with(map[string]any{"note": "x"}), public, nil)
	signed("missing", nil, public, nil)
	signed("another key", sig, otherPublic, nil)
	signed("a key that is not base64", sig, "not a key", nil)
	signed("a key of the wrong length", sig, "AAAA", nil)
	signed("not JSON", "{", public, nil)
	signed("a list", "[]", public, nil)
	signed("no signature", with(map[string]any{"signature": "<absent>"}), public, nil)
	signed("signature a number", with(map[string]any{"signature": 5}), public, nil)
	signed("signature not base64", with(map[string]any{"signature": "!!!"}), public, nil)
	signed("signature too short", with(map[string]any{"signature": "AAAA"}), public, nil)
	signed("signature with a newline", with(map[string]any{"signature": sigDoc["signature"].(string)[:40] + "\n" + sigDoc["signature"].(string)[40:]}), public, nil)
	signed("another version", with(map[string]any{"version": "00"}), public, nil)
	signed("no files", with(map[string]any{"files": "<absent>"}), public, nil)
	signed("alg and key_id are not checked", with(map[string]any{"alg": "none", "key_id": "x"}), public, nil)
	signed("a file changed", sig, public, map[string]any{"catalog.json": "{}"})
	signed("a file removed", sig, public, map[string]any{"roles.json": nil})
	signed("a file reformatted", sig, public, map[string]any{"roles.json": strings.ReplaceAll(string(MarshalJSON(baseBundle()["roles.json"])), ",", ",\r\n")})
	signed("unsigned additions do not matter", sig, public, map[string]any{"tests/t.json": "{}"})
	signed("an empty key means unsigned is fine", nil, "", nil)

	var ref *refProcess
	if havePython(t) {
		ref = startPython(t, engineScript)
	} else {
		t.Logf("not compared with the Python reference: %s", pyReason)
	}

	signingKey, _, _ := Keygen()
	loaded, refused, mismatches := 0, 0, 0
	codes := map[string]int{}
	versions := map[string]string{}
	for _, s := range shapes {
		dir := t.TempDir()
		writeBundle(t, dir, baseBundle())
		writeBundle(t, dir, s.files)
		cfg := map[string]any{"bundle_dir": dir, "trust_caller_chain": true, "allow_test_clock": true, "signing_key": signingKey}
		for k, v := range s.config {
			cfg[k] = v
		}
		mine := map[string]any{"ok": true}
		e, err := NewEngine(cfg)
		if err != nil {
			mine = map[string]any{"ok": false, "error": map[string]any{"code": err.(*EngineError).Code}}
			refused++
			codes[err.(*EngineError).Code]++
		} else {
			loaded++
			mine["info"] = e.Call("info", map[string]any{})
			mine["decision"] = e.Call("filter", map[string]any{"chain": map[string]any{"user": "u", "agents": []any{"a"}}, "action": "read",
				"resource": map[string]any{"path": "t.item", "id": "i"}, "data": map[string]any{"a": int64(1), "b": int64(2), "c": int64(3)}, "now": testNow, "explain": true})
			versions[s.name] = mine["info"].(map[string]any)["policy_version"].(string)
			e.Close()
		}
		if ref == nil {
			continue
		}
		theirs := mustParse(t, ref.line(Canon(map[string]any{"new": cfg}))).(map[string]any)
		if theirs["ok"] == true {
			theirs["info"] = mustParse(t, ref.line(Canon(map[string]any{"op": "info", "input": map[string]any{}})))
			theirs["decision"] = mustParse(t, ref.line(Canon(map[string]any{"op": "filter", "input": map[string]any{"chain": map[string]any{"user": "u", "agents": []any{"a"}},
				"action": "read", "resource": map[string]any{"path": "t.item", "id": "i"}, "data": map[string]any{"a": int64(1), "b": int64(2), "c": int64(3)}, "now": testNow, "explain": true}})))
		}
		if a, b := Canon(scrub(mine, nil)), Canon(scrub(theirs, nil)); a != b {
			mismatches++
			if mismatches <= 20 {
				t.Errorf("%s:\n  go        %.900s\n  reference %.900s", s.name, a, b)
			}
		}
	}
	// what must hold whether or not the reference is here
	if versions["CRLF line endings"] == "" || versions["CRLF line endings"] != versions["LF line endings, same content"] {
		t.Errorf("line endings change the version: %q %q", versions["CRLF line endings"], versions["LF line endings, same content"])
	}
	if versions["the base bundle"] == "" || versions["the base bundle"] != versions["a tests directory and other files are not part of the version"] ||
		versions["the base bundle"] == versions["only policies.json"] || versions["a lone CR is content"] == versions["CRLF line endings"] {
		t.Errorf("bundle versions: %v", versions)
	}
	for _, code := range []string{"bundle_io", "policy_parse", "entities_parse", "catalog_parse", "roles_parse", "bundle_stale", "bundle_unsigned", "bundle_signature", "crypto"} {
		if codes[code] == 0 {
			t.Errorf("no shape was refused with %s", code)
		}
	}
	if loaded < 100 || refused < 200 {
		t.Errorf("expected at least 100 bundles to load and 200 to be refused, got %d and %d", loaded, refused)
	}
	t.Logf("bundle shapes: %d loaded, %d refused %v; compared with the reference: %v, %d mismatches", loaded, refused, codes, ref != nil, mismatches)
}

// One bundle whose permits carry every form of row filter, rate limit and
// approval annotation, and whose catalog uses every form of labels and mask.
// The same requests go to both engines.
func TestInteropAnnotations(t *testing.T) {
	item := expr(`{"op": "is", "entity_type": "Item"}`)
	policies := map[string]any{
		"fields": policy(map[string]any{"resource": expr(`{"op": "is", "entity_type": "Field"}`), "conditions": []any{map[string]any{"kind": "unless",
			"body": expr(`{"contains": {"left": {".": {"left": {"Var": "resource"}, "attr": "labels"}}, "right": {"Value": "x"}}}`)}}}),
		"approvers": policy(map[string]any{"principal": expr(`{"op": "==", "entity": {"type": "User", "id": "v"}}`), "action": expr(`{"op": "==", "entity": {"type": "Action", "id": "approve"}}`)}),
		"forbid-with-annotations": policy(map[string]any{"effect": "forbid", "action": expr(`{"op": "==", "entity": {"type": "Action", "id": "never"}}`),
			"annotations": map[string]any{"row_filter": "status = broken", "rate_limit": "x", "require_approval": "no"}}),
	}
	var actions []string
	variant := func(annotations map[string]any) {
		name := fmt.Sprintf("act%03d", len(actions))
		actions = append(actions, name)
		policies[name] = policy(map[string]any{"action": map[string]any{"op": "==", "entity": map[string]any{"type": "Action", "id": name}}, "resource": item, "annotations": annotations})
	}
	for _, rf := range []any{
		`status == "open"`, `status == "open" && n == 42 && neg == -7`, `owner == context.owner.id && flag == context.flag`, `owner == context.iam.user_id`,
		`region == context.iam.user_attrs.region`, `status = open`, `a == b`, `a.b == 1`, ``, `x == "a" && `, `  col  ==  "v w"  `, `a == "x==y"`, `a == ""`, `a == "`, `n == 007`,
		`n == -`, `n == --1`, `n == +1`, `n == 99999999999999999999`, `n == -99999999999999999999`, `status == 'open'`, `n == 42 && n == 42`, `n == context.iam.depth`,
		`n == context.iam.chain`, `n == context.missing`, `n == context.`, `flag == context.flag.x`, `status == "open" || n == 1`, `Status == "open"`, `status== "open"&&n==42`,
		"\u00e9 == 1", "n == \u0664\u0662", "n == -\u0664\u0662", "n == \u00b2", "n\u00a0==\u200942", "status == \"\u00e9\U0001F600\"", `n == context.n`, `n == context.deep.a.b`,
		`n==42&&&&n==42`, `==`, `n ==`, ` == 1`, `n == 4 2`, `n == "4" "2"`, `n_1 == 1`, `1 == 1`, `status == "open" && owner == context.owner.id`, 5, nil, true, []any{},
	} {
		variant(map[string]any{"row_filter": rf})
	}
	for _, rl := range []any{"3/60", " 2 / 60 ", "3/0", "x", "", "3/60/1", "0/5", "1/1", "\u0663/\u0666\u0660", "2/99999999999999999999", "99999999999999999999/5", "-1/5", "1/-5",
		"1.5/5", "3 /\t60\n", "\u00a03/60\u2003", "3/60s", 5, 0, nil, true} {
		variant(map[string]any{"rate_limit": rl})
	}
	for _, label := range []any{"needs-a-human", "", nil, 5, []any{"x", int64(1)}, map[string]any{"a": true}, "\u00e9\U0001F600\u2028"} {
		variant(map[string]any{"require_approval": label})
	}
	variant(map[string]any{"row_filter": `status == "open"`, "rate_limit": "2/10", "require_approval": "all three", "id": "x", "other": "ignored"})
	variant(map[string]any{})
	bundle := map[string]any{
		"policies.json": map[string]any{"policies": policies},
		"entities.json": expr(`[{"uid": {"type": "User", "id": "u"}, "attrs": {"region": "EU"}}, {"uid": {"type": "User", "id": "v"}}, {"uid": {"type": "Agent", "id": "a"}}]`),
		"catalog.json": expr(`{"resources": {"t.item": {"entity_type": "Item", "fields": {"a": {}, "b": {"labels": "xy"}, "c": {"labels": ["l1", 5, ["n"]]},
			"d": {"mask": "redact", "labels": ["x"]}, "e": {"mask": "drop", "labels": ["x"]}, "f.g": {}, "h[]": {}, "h[].i": {"mask": "redact", "labels": ["x"]},
			"owner": {}, "status": {}, "n": {}, "neg": {}, "flag": {}, "col": {}, "region": {}, "k": {"labels": {"x": 1}}}}}}`),
	}
	dir := t.TempDir()
	writeBundle(t, dir, bundle)

	rows := expr(`[{"status": "open", "n": 42, "neg": -7, "owner": "o1", "flag": true, "a": "x==y", "col": "v w", "region": "EU", "b": 1, "c": 2, "d": 3, "e": 4,
			"f": {"g": 1, "z": 2}, "h": [{"i": 1, "j": 2}, 5], "k": 1},
		{"status": "open", "n": 42.0, "neg": -7, "owner": "u", "flag": 1, "a": "", "region": "US"},
		{"status": "closed", "n": 7, "owner": "o1", "flag": true, "a": "\""},
		{"status": "open", "n": 99999999999999999999, "owner": 5, "flag": "yes"},
		{"n": 1, "status": "open"}, {"n": true}, {"status": "\u00e9\ud83d\ude00", "n": -99999999999999999999}, {}, "row", null]`)
	contexts := []any{expr(`{}`), expr(`{"owner": {"id": "o1"}, "flag": true, "n": 42, "deep": {"a": {"b": 42}}}`), expr(`{"owner": {"id": 5}, "flag": "yes", "n": "42", "deep": {"a": 42}}`),
		expr(`{"owner": "x", "flag": [true], "n": {"v": 42}, "missing": {"__entity": {"type": "User", "id": "u"}}}`)}
	chain := map[string]any{"user": "u", "agents": []any{"a"}}
	type step struct {
		op    string
		input map[string]any
	}
	var steps []step
	for _, action := range append(append([]string{}, actions...), "never", "unknown") {
		for _, ctx := range contexts {
			in := map[string]any{"chain": chain, "action": action, "resource": map[string]any{"path": "t.item", "id": "i"}, "context": ctx, "now": testNow}
			withData := map[string]any{"data": rows}
			for k, v := range in {
				withData[k] = v
			}
			steps = append(steps, step{"authorize", in}, step{"filter", withData})
		}
		// the same request again and again: rate limits, and approvals asked twice
		in := map[string]any{"chain": chain, "action": action, "resource": map[string]any{"path": "t.item", "id": "i"}, "now": testNow + 1}
		steps = append(steps, step{"authorize", in}, step{"authorize", in}, step{"authorize", in}, step{"explain", in})
	}
	steps = append(steps, step{"approvals", map[string]any{}})

	signingKey, _, _ := Keygen()
	config := func(state string) map[string]any {
		return map[string]any{"bundle_dir": dir, "state_dir": state, "trust_caller_chain": true, "allow_test_clock": true, "signing_key": signingKey}
	}
	e, err := NewEngine(config(filepath.Join(t.TempDir(), "go")))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var ref *refProcess
	if havePython(t) {
		ref = startPython(t, engineScript)
		if started := ref.line(Canon(map[string]any{"new": config(filepath.Join(t.TempDir(), "reference"))})); !strings.Contains(started, `"ok": true`) {
			t.Fatalf("the reference did not load the bundle: %s", started)
		}
	} else {
		t.Logf("not compared with the Python reference: %s", pyReason)
	}
	run := func(s step) (map[string]any, map[string]any) {
		mine := e.Call(s.op, s.input)
		if ref == nil {
			return mine, nil
		}
		return mine, mustParse(t, ref.line(Canon(map[string]any{"op": s.op, "input": s.input}))).(map[string]any)
	}
	mismatches := 0
	reasons := map[string]int{}
	compare := func(s step, mine, theirs map[string]any) {
		key := errCode(mine)
		if r, ok := mine["reason"].(string); ok {
			key = r
		}
		reasons[key]++
		if theirs == nil {
			return
		}
		if a, b := Canon(scrub(mine, nil)), Canon(scrub(theirs, nil)); a != b {
			mismatches++
			if mismatches <= 15 {
				t.Errorf("%s %.300s\n  go        %.1200s\n  reference %.1200s", s.op, Canon(s.input), a, b)
			}
		}
	}
	var pending map[string]any
	for _, s := range steps {
		mine, theirs := run(s)
		compare(s, mine, theirs)
		if s.op == "approvals" {
			pending, _ = mine["pending"].(map[string]any)
		}
	}
	// approve everything that is held (by the user itself, then by someone allowed), and ask again
	for _, id := range sortedKeys(pending) {
		for _, by := range []string{"u", "v", "v"} {
			s := step{"approve", map[string]any{"approval_id": id, "by": by, "now": testNow + 2}}
			mine, theirs := run(s)
			compare(s, mine, theirs)
		}
	}
	for _, action := range actions {
		in := map[string]any{"chain": chain, "action": action, "resource": map[string]any{"path": "t.item", "id": "i"}, "now": testNow + 3}
		for _, s := range []step{{"authorize", in}, {"authorize", in}} {
			mine, theirs := run(s)
			compare(s, mine, theirs)
		}
	}
	for _, s := range []step{{"approvals", map[string]any{}}, {"audit_verify", map[string]any{}}, {"audit_tail", map[string]any{"n": 30}}} {
		mine, theirs := run(s)
		compare(s, mine, theirs)
	}
	for _, want := range []string{"policy_permit", "policy_error", "obligation_unresolved", "rate_limited", "approval_required", "internal", "policy_forbid", "no_matching_permit"} {
		if reasons[want] == 0 {
			t.Errorf("no request ended in %s: %v", want, reasons)
		}
	}
	if len(pending) < 5 {
		t.Errorf("expected held requests, got %d", len(pending))
	}
	t.Logf("annotations: %d variants, %d requests %v; compared with the reference: %v, %d mismatches", len(actions), len(steps), reasons, ref != nil, mismatches)
}
