package smartdelegate

import (
	"encoding/json"
	"math"
	"math/big"
	"strings"
	"testing"
)

func mustParse(t *testing.T, text string) any {
	t.Helper()
	v, err := ParseJSON([]byte(text))
	if err != nil {
		t.Fatalf("ParseJSON(%q): %v", text, err)
	}
	return v
}

func TestCanonicalJSON(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{` { "b" : [ 1 , 2 , { "z" : null , "y" : true } ] , "a" : false } `, `{"a":false,"b":[1,2,{"y":true,"z":null}]}`},
		{`{}`, `{}`}, {`[]`, `[]`}, {`""`, `""`}, {`0`, `0`}, {`-0`, `0`},
		// integers stay exact: beyond 2^53, the 64-bit limits, and beyond them
		{`[9007199254740993,-9223372036854775808,9223372036854775807]`, `[9007199254740993,-9223372036854775808,9223372036854775807]`},
		{`[9223372036854775808,-123456789012345678901234567890]`, `[9223372036854775808,-123456789012345678901234567890]`},
		// escapes: quote, backslash, the five short forms, other controls as \u00xx in lowercase
		{`"\"\\\/\b\f\n\r\t\u0000\u001f\u007f"`, `"\"\\/\b\f\n\r\t\u0000\u001f` + "\x7f" + `"`},
		{`"\u000b\u001B\u000E"`, `"\u000b\u001b\u000e"`},
		// everything else is written as itself, never \u-escaped
		{`"\u00e9\u20ac\ud83d\ude00\u2028\u0085"`, "\"\u00e9\u20ac\U0001f600\u2028\u0085\""},
		{"\"\u00e9\u20ac\U0001f600\"", "\"\u00e9\u20ac\U0001f600\""},
		// key order is by code point: U+E000 and U+FFFF sort before U+10000 and
		// U+1F600 (UTF-16 order would put the surrogate pairs first)
		{`{"\ud83d\ude00":1,"\uffff":2,"\ue000":3,"\ud800\udc00":4,"z":5,"Z":6,"":7,"a\u0000":8,"a":9,"\u00e9":10,"e":11}`,
			"{\"\":7,\"Z\":6,\"a\":9,\"a\\u0000\":8,\"e\":11,\"z\":5,\"\u00e9\":10,\"\ue000\":3,\"\uffff\":2,\"\U00010000\":4,\"\U0001f600\":1}"},
		// the last of duplicate keys wins
		{`{"a":1,"a":2}`, `{"a":2}`},
	}
	for _, c := range cases {
		if got := Canon(mustParse(t, c.in)); got != c.want {
			t.Errorf("Canon(%s)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	if got := hashValue(map[string]any{"b": int64(1), "a": []any{"x", nil}}); got != sha256Hex([]byte(`{"a":["x",null],"b":1}`)) {
		t.Errorf("hashValue does not hash the canonical form: %s", got)
	}
}

func TestCanonAcceptsGoValues(t *testing.T) {
	type pair struct {
		A int    `json:"a"`
		B string `json:"b"`
	}
	v := map[string]any{
		"ints": []int{1, 2}, "u": uint64(math.MaxUint64), "i8": int8(-3), "s": []string{"x"}, "m": map[string]string{"k": "v"},
		"n": json.Number("12345678901234567890"), "f32": float32(0.5), "big": big.NewInt(7), "p": &pair{1, "z"}, "nilptr": (*pair)(nil),
		"nested": []map[string]any{{"a": 1}}, "nilslice": []any(nil), "nilmap": map[string]any(nil),
	}
	want := `{"big":7,"f32":0.5,"i8":-3,"ints":[1,2],"m":{"k":"v"},"n":12345678901234567890,"nested":[{"a":1}],"nilmap":{},"nilptr":null,"nilslice":[],"p":{"a":1,"b":"z"},"s":["x"],"u":18446744073709551615}`
	if got := Canon(v); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if _, err := normalize(map[string]any{"f": func() {}}, 0); err == nil {
		t.Error("a func is not a JSON value")
	}
	if _, err := normalize(map[int]string{1: "a"}, 0); err == nil {
		t.Error("a map with non-string keys is not a JSON value")
	}
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	if _, err := normalize(cyclic, 0); err != errTooDeep {
		t.Errorf("a cyclic value must be refused, got %v", err)
	}
}

func TestParseJSONNumbers(t *testing.T) {
	arr := mustParse(t, `[1, -1, 0, 9223372036854775807, -9223372036854775808, 9223372036854775808, 1.0, 1e2, 1E-2, -0.0, 10000000000000000000000]`).([]any)
	wantKinds := []string{"int", "int", "int", "int", "int", "int", "float", "float", "float", "float", "int"}
	for i, v := range arr {
		if jsonKind(v) != wantKinds[i] {
			t.Errorf("element %d: %T", i, v)
		}
	}
	if arr[3] != int64(math.MaxInt64) || arr[4] != int64(math.MinInt64) {
		t.Errorf("64-bit limits are not exact: %v %v", arr[3], arr[4])
	}
	if b, ok := arr[5].(*big.Int); !ok || b.String() != "9223372036854775808" {
		t.Errorf("an integer beyond 64 bits must stay exact, got %T %v", arr[5], arr[5])
	}
	for _, v := range arr {
		if f, ok := v.(float64); ok && f == math.Trunc(f) && jsonKind(v) != "float" {
			t.Errorf("unexpected float %v", v)
		}
	}
	if v := mustParse(t, `[NaN, Infinity, -Infinity, 1e999]`).([]any); !math.IsNaN(v[0].(float64)) || !math.IsInf(v[1].(float64), 1) || !math.IsInf(v[2].(float64), -1) || !math.IsInf(v[3].(float64), 1) {
		t.Errorf("the reference's non-finite numbers: %v", v)
	}
}

func TestParseJSONRejects(t *testing.T) {
	bad := []string{``, ` `, `{`, `[1,]`, `{"a":1,}`, `{a:1}`, `'a'`, `01`, `1.`, `.5`, `-`, `+1`, `1e`, `"\x"`, `"\u12"`, "\"a\nb\"", "\"\x01\"",
		`nul`, `tru`, `[1 2]`, `{"a" 1}`, `1 2`, `"abc`, `{"a":1}}`, "\xff", "\"\xc3\x28\"", `nan`, `infinity`, "\xef\xbb\xbf1",
		strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1)}
	for _, s := range bad {
		if v, err := ParseJSON([]byte(s)); err == nil {
			t.Errorf("ParseJSON(%q) = %v, want an error", s, v)
		}
	}
	good := []string{`1`, ` [ ] `, "\t{\r\n}\n", `"\ud800"`, `"\udc00\ud800"`, `1E+2`, `-0`, strings.Repeat("[", maxDepth) + strings.Repeat("]", maxDepth)}
	for _, s := range good {
		if _, err := ParseJSON([]byte(s)); err != nil {
			t.Errorf("ParseJSON(%q): %v", s, err)
		}
	}
	if v, err := parseJSONBytes([]byte("\xef\xbb\xbf{}")); err != nil || len(v.(map[string]any)) != 0 {
		t.Errorf("a byte order mark before bytes is accepted by the reference: %v %v", v, err)
	}
}

func TestFloatRepr(t *testing.T) {
	// the reference writes floats with Python's repr
	cases := map[string]string{
		"1.0": "1.0", "1.5": "1.5", "-0.0": "-0.0", "0.0": "0.0", "1e15": "1000000000000000.0", "1e16": "1e+16", "1.5e16": "1.5e+16",
		"123456789012345680.0": "1.2345678901234568e+17", "0.0001": "0.0001", "0.00001": "1e-05", "1.5e-7": "1.5e-07", "1e100": "1e+100",
		"5e-324": "5e-324", "1.7976931348623157e308": "1.7976931348623157e+308", "100.0": "100.0", "123456.789e3": "123456789.0",
		"0.1": "0.1", "-1E-2": "-0.01", "3.14159": "3.14159", "9999999999999998.0": "9999999999999998.0", "NaN": "NaN", "-Infinity": "-Infinity",
		"1e22": "1e+22", "0.30000000000000004": "0.30000000000000004",
	}
	for in, want := range cases {
		if got := Canon(mustParse(t, in)); got != want {
			t.Errorf("float %s: got %s, want %s", in, got, want)
		}
	}
}

func TestLooseEquality(t *testing.T) {
	eq := func(a, b string) bool { return pyEqual(mustParse(t, a), mustParse(t, b)) }
	for _, c := range [][2]string{{`1`, `1.0`}, {`1`, `true`}, {`0`, `false`}, {`[1,{"a":[true]}]`, `[1.0,{"a":[1]}]`}, {`null`, `null`},
		{`9223372036854775808`, `9223372036854775808`}, {`9007199254740993`, `9007199254740993`}, {`{}`, `{}`}} {
		if !eq(c[0], c[1]) {
			t.Errorf("%s == %s in the reference", c[0], c[1])
		}
	}
	for _, c := range [][2]string{{`1`, `"1"`}, {`null`, `false`}, {`null`, `0`}, {`[]`, `{}`}, {`9007199254740993`, `9007199254740992.0`},
		{`NaN`, `NaN`}, {`[1]`, `[1,1]`}, {`{"a":1}`, `{"b":1}`}, {`""`, `[]`}, {`9223372036854775808`, `9223372036854775807`}} {
		if eq(c[0], c[1]) {
			t.Errorf("%s != %s in the reference", c[0], c[1])
		}
	}
	// a row filter and the vector runner tell true from 1 and 1 from 1.0 at the top level
	if sameJSON(int64(1), true) || sameJSON(int64(1), 1.0) || !sameJSON(int64(1), int64(1)) {
		t.Error("sameJSON must compare JSON types")
	}
	if Subset(mustParse(t, `{"a":true}`), mustParse(t, `{"a":1}`), "") == "" || Subset(mustParse(t, `{"a":null}`), mustParse(t, `{}`), "") != "" ||
		Subset(mustParse(t, `{"a":{"b":[1]}}`), mustParse(t, `{"a":{"b":[1],"c":2},"d":3}`), "") != "" ||
		Subset(mustParse(t, `{"a":{"b":[1]}}`), mustParse(t, `{"a":{"b":[2]}}`), "") == "" || Subset(mustParse(t, `{"a":1}`), mustParse(t, `{}`), "") == "" {
		t.Error("Subset does not follow the runner's rules")
	}
}

func TestStrip(t *testing.T) {
	if strip("\u2028 \x1f a \t\n\u00a0") != "a" {
		t.Error("strip")
	}
}
