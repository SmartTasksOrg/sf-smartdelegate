package smartdelegate

// JSON values, canonical JSON and SHA-256 helpers.
//
// A JSON value in this package is one of:
//
//	nil, bool, int64, *big.Int (an integer outside 64 bits), float64,
//	string, []any, map[string]any
//
// Integers never become float64. The audit hash chain, approval ids, bundle
// versions and bundle signatures depend on Canon being byte-identical in
// every port: keys sorted by code point, no whitespace, non-ASCII characters
// written as themselves, control characters as \u00xx (lowercase).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxDepth bounds the nesting of any JSON value the engine reads or is given.
const maxDepth = 1000

// ---- parsing ---------------------------------------------------------------

type jsonParser struct {
	s     []byte
	i     int
	depth int
}

// ParseJSON parses one JSON document. Integers stay exact (int64, or
// *big.Int when they do not fit); numbers with a fraction or an exponent are
// float64. Like the reference's parser it also accepts NaN, Infinity and
// -Infinity, and keeps the last of duplicate keys.
func ParseJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	p := &jsonParser{s: data}
	p.ws()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("extra data at offset %d", p.i)
	}
	return v, nil
}

// parseJSONBytes is ParseJSON for bytes that may start with a UTF-8 byte
// order mark (the reference accepts one when it parses bytes).
func parseJSONBytes(data []byte) (any, error) {
	return ParseJSON(stripBOM(data))
}

func stripBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}

func (p *jsonParser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *jsonParser) errf(format string, a ...any) error {
	return fmt.Errorf("%s at offset %d", fmt.Sprintf(format, a...), p.i)
}

func (p *jsonParser) lit(word string) bool {
	if strings.HasPrefix(string(p.s[p.i:min(len(p.s), p.i+len(word))]), word) {
		p.i += len(word)
		return true
	}
	return false
}

func (p *jsonParser) value() (any, error) {
	if p.i >= len(p.s) {
		return nil, p.errf("expecting value")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		return p.str()
	case c == 'n' && p.lit("null"):
		return nil, nil
	case c == 't' && p.lit("true"):
		return true, nil
	case c == 'f' && p.lit("false"):
		return false, nil
	case c == 'N' && p.lit("NaN"):
		return math.NaN(), nil
	case c == 'I' && p.lit("Infinity"):
		return math.Inf(1), nil
	case c == '-' && p.lit("-Infinity"):
		return math.Inf(-1), nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return nil, p.errf("expecting value")
}

func (p *jsonParser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	digits := func() int {
		n := 0
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.i < len(p.s) && p.s[p.i] == '0' {
		p.i++
	} else if digits() == 0 {
		p.i = start
		return nil, p.errf("expecting value")
	}
	isFloat := false
	if p.i+1 < len(p.s) && p.s[p.i] == '.' && p.s[p.i+1] >= '0' && p.s[p.i+1] <= '9' {
		p.i++
		digits()
		isFloat = true
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		save := p.i
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			p.i = save
		} else {
			isFloat = true
		}
	}
	text := string(p.s[start:p.i])
	if isFloat {
		f, err := strconv.ParseFloat(text, 64)
		if err != nil && !math.IsInf(f, 0) {
			return nil, p.errf("bad number")
		}
		return f, nil
	}
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		return n, nil
	}
	b, ok := new(big.Int).SetString(text, 10)
	if !ok {
		return nil, p.errf("bad number")
	}
	return b, nil
}

func (p *jsonParser) hex4() (rune, bool) {
	if p.i+4 > len(p.s) {
		return 0, false
	}
	var r rune
	for _, c := range p.s[p.i : p.i+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	p.i += 4
	return r, true
}

func (p *jsonParser) str() (string, error) {
	p.i++ // opening quote
	var b []byte
	start := p.i
	for {
		if p.i >= len(p.s) {
			return "", p.errf("unterminated string")
		}
		c := p.s[p.i]
		if c == '"' {
			var out string
			if b == nil {
				out = string(p.s[start:p.i])
			} else {
				out = string(append(b, p.s[start:p.i]...))
			}
			p.i++
			return out, nil
		}
		if c < 0x20 {
			return "", p.errf("invalid control character")
		}
		if c != '\\' {
			p.i++
			continue
		}
		b = append(b, p.s[start:p.i]...)
		p.i++
		if p.i >= len(p.s) {
			return "", p.errf("unterminated string")
		}
		e := p.s[p.i]
		p.i++
		switch e {
		case '"', '\\', '/':
			b = append(b, e)
		case 'b':
			b = append(b, '\b')
		case 'f':
			b = append(b, '\f')
		case 'n':
			b = append(b, '\n')
		case 'r':
			b = append(b, '\r')
		case 't':
			b = append(b, '\t')
		case 'u':
			r, ok := p.hex4()
			if !ok {
				return "", p.errf("invalid \\u escape")
			}
			if r >= 0xD800 && r < 0xDC00 && p.i+1 < len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
				save := p.i
				p.i += 2
				if lo, ok := p.hex4(); ok && lo >= 0xDC00 && lo < 0xE000 {
					r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
				} else {
					p.i = save
				}
			}
			// a lone surrogate has no UTF-8 form; it becomes U+FFFD
			b = utf8.AppendRune(b, r)
		default:
			p.i--
			return "", p.errf("invalid escape")
		}
		start = p.i
	}
}

func (p *jsonParser) array() (any, error) {
	if p.depth++; p.depth > maxDepth {
		return nil, p.errf("nested too deeply")
	}
	defer func() { p.depth-- }()
	p.i++
	out := []any{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return out, nil
	}
	for {
		p.ws()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.ws()
		if p.i >= len(p.s) {
			return nil, p.errf("expecting ',' or ']'")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == ']' {
			p.i++
			return out, nil
		}
		return nil, p.errf("expecting ',' or ']'")
	}
}

func (p *jsonParser) object() (any, error) {
	if p.depth++; p.depth > maxDepth {
		return nil, p.errf("nested too deeply")
	}
	defer func() { p.depth-- }()
	p.i++
	out := map[string]any{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return out, nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, p.errf("expecting property name")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.errf("expecting ':'")
		}
		p.i++
		p.ws()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out[k] = v
		p.ws()
		if p.i >= len(p.s) {
			return nil, p.errf("expecting ',' or '}'")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == '}' {
			p.i++
			return out, nil
		}
		return nil, p.errf("expecting ',' or '}'")
	}
}

// ---- writing ---------------------------------------------------------------

const hexDigits = "0123456789abcdef"

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		b.WriteString(s[start:i])
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			b.WriteString(`\u00`)
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xF])
		}
		start = i + 1
	}
	b.WriteString(s[start:])
	b.WriteByte('"')
}

// floatRepr writes a float the way the reference does (Python's repr, and
// NaN / Infinity for the values JSON has no form for).
func floatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d[.ddd]e+-dd
	neg := strings.HasPrefix(e, "-")
	e = strings.TrimPrefix(e, "-")
	mant, expText, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expText)
	digits := strings.Replace(mant, ".", "", 1)
	decpt := exp + 1
	var out string
	switch {
	case decpt > 16 || decpt <= -4:
		out = digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		sign := "+"
		if exp < 0 {
			sign, exp = "-", -exp
		}
		out += fmt.Sprintf("e%s%02d", sign, exp)
	case decpt <= 0:
		out = "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		out = digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		out = digits[:decpt] + "." + digits[decpt:]
	}
	if neg {
		return "-" + out
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // bytewise on UTF-8, which is code point order
	return keys
}

// writeValue writes v. indent < 0 is the compact form (no whitespace);
// otherwise objects and arrays are broken over lines like the reference CLI.
func writeValue(b *strings.Builder, v any, indent, level int) {
	nl := func(l int) {
		if indent >= 0 {
			b.WriteByte('\n')
			b.WriteString(strings.Repeat(" ", indent*l))
		}
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case *big.Int:
		b.WriteString(x.String())
	case float64:
		b.WriteString(floatRepr(x))
	case string:
		writeString(b, x)
	case []any:
		if len(x) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteByte('[')
		for i, el := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			nl(level + 1)
			writeValue(b, el, indent, level+1)
		}
		nl(level)
		b.WriteByte(']')
	case map[string]any:
		if len(x) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteByte('{')
		for i, k := range sortedKeys(x) {
			if i > 0 {
				b.WriteByte(',')
			}
			nl(level + 1)
			writeString(b, k)
			b.WriteByte(':')
			if indent >= 0 {
				b.WriteByte(' ')
			}
			writeValue(b, x[k], indent, level+1)
		}
		nl(level)
		b.WriteByte('}')
	default:
		n, err := normalize(v, 0)
		if err != nil {
			panic(err)
		}
		writeValue(b, n, indent, level)
	}
}

// Canon is the canonical JSON form of a value.
func Canon(v any) string {
	var b strings.Builder
	writeValue(&b, v, -1, 0)
	return b.String()
}

// MarshalJSON writes a value compactly (the canonical form).
func MarshalJSON(v any) []byte { return []byte(Canon(v)) }

// MarshalIndent writes a value over several lines, two spaces per level.
func MarshalIndent(v any) string {
	var b strings.Builder
	writeValue(&b, v, 2, 0)
	return b.String()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hashValue(v any) string { return sha256Hex([]byte(Canon(v))) }

// ---- Go values -> JSON values ------------------------------------------------

// normalize deep-copies a value into the JSON model above. It accepts what a
// Go caller is likely to hand in (int, []string, map[string]string,
// json.Number, ...). A float64 stays a float: decode request bodies with
// ParseJSON, or with json.Decoder.UseNumber, to keep integers exact.
func normalize(v any, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errTooDeep
	}
	switch x := v.(type) {
	case nil, bool, string, int64, float64:
		return x, nil
	case int:
		return int64(x), nil
	case *big.Int:
		if x == nil {
			return nil, nil
		}
		if x.IsInt64() {
			return x.Int64(), nil
		}
		return new(big.Int).Set(x), nil
	case json.Number:
		n, err := ParseJSON([]byte(x.String()))
		if err != nil {
			return nil, fmt.Errorf("not a JSON number: %q", x.String())
		}
		return n, nil
	case []any:
		out := make([]any, len(x))
		for i, el := range x {
			n, err := normalize(el, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, el := range x {
			n, err := normalize(el, depth+1)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	case []string:
		out := make([]any, len(x))
		for i, el := range x {
			out[i] = el
		}
		return out, nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Bool:
		return rv.Bool(), nil
	case reflect.String:
		return rv.String(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		u := rv.Uint()
		if u <= math.MaxInt64 {
			return int64(u), nil
		}
		return new(big.Int).SetUint64(u), nil
	case reflect.Float32, reflect.Float64:
		return rv.Float(), nil
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil, nil
		}
		return normalize(rv.Elem().Interface(), depth+1)
	case reflect.Slice, reflect.Array:
		out := make([]any, rv.Len())
		for i := range out {
			n, err := normalize(rv.Index(i).Interface(), depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("not a JSON value: %T", v)
		}
		out := make(map[string]any, rv.Len())
		for it := rv.MapRange(); it.Next(); {
			n, err := normalize(it.Value().Interface(), depth+1)
			if err != nil {
				return nil, err
			}
			out[it.Key().String()] = n
		}
		return out, nil
	case reflect.Struct:
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("not a JSON value: %T", v)
		}
		return ParseJSON(raw)
	}
	return nil, fmt.Errorf("not a JSON value: %T", v)
}

var errTooDeep = errors.New("nested too deeply")

// ---- the reference's loose comparisons ----------------------------------------

// truthy is Python truthiness of a JSON value.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int64:
		return x != 0
	case *big.Int:
		return x.Sign() != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func asNumber(v any) (*big.Float, bool, bool) { // value, is a number, is NaN
	switch x := v.(type) {
	case bool:
		if x {
			return big.NewFloat(1), true, false
		}
		return big.NewFloat(0), true, false
	case int64:
		return new(big.Float).SetPrec(128).SetInt64(x), true, false
	case *big.Int:
		return new(big.Float).SetPrec(uint(x.BitLen() + 64)).SetInt(x), true, false
	case float64:
		if math.IsNaN(x) {
			return nil, true, true
		}
		return big.NewFloat(x), true, false
	}
	return nil, false, false
}

// pyEqual is Python's == on JSON values: numbers compare by value whatever
// their type (true == 1 == 1.0), containers compare element by element.
func pyEqual(a, b any) bool {
	na, aNum, aNaN := asNumber(a)
	nb, bNum, bNaN := asNumber(b)
	if aNum || bNum {
		return aNum && bNum && !aNaN && !bNaN && na.Cmp(nb) == 0
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !pyEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, ok := y[k]
			if !ok || !pyEqual(xv, yv) {
				return false
			}
		}
		return true
	}
	return false
}

// jsonKind names the JSON type of a value; bool, integer and float differ.
func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case int64, *big.Int:
		return "int"
	case float64:
		return "float"
	case string:
		return "string"
	case []any:
		return "list"
	case map[string]any:
		return "object"
	}
	return "other"
}

func isSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// strip removes leading and trailing whitespace as the reference does.
func strip(s string) string { return strings.TrimFunc(s, isSpace) }

func strList(items []string) []any {
	out := make([]any, len(items))
	for i, s := range items {
		out[i] = s
	}
	return out
}
