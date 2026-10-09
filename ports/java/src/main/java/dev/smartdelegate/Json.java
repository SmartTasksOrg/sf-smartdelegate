package dev.smartdelegate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small JSON reader and writer so the SDK has no dependencies. The reader
 * accepts RFC 8259 JSON and nothing looser; integers must fit 64 bits.
 * Objects are {@code Map<String,Object>}, arrays {@code List<Object>},
 * integers {@code Long}, other numbers {@code Double}.
 */
public final class Json {
    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    public static Object parse(String text) {
        Json p = new Json(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != text.length()) throw new IllegalArgumentException("trailing characters at " + p.i);
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object v = parse(text);
        if (!(v instanceof Map)) throw new IllegalArgumentException("not a JSON object");
        return (Map<String, Object>) v;
    }

    private void ws() {
        // JSON's four whitespace characters, nothing else
        while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t' || s.charAt(i) == '\n' || s.charAt(i) == '\r')) i++;
    }

    private Object value() {
        if (i >= s.length()) throw new IllegalArgumentException("unexpected end");
        char c = s.charAt(i);
        if (c == '{') return object();
        if (c == '[') return array();
        if (c == '"') return string();
        if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
        if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
        if (s.startsWith("null", i)) { i += 4; return null; }
        return number();
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<>();
        i++;
        ws();
        if (s.charAt(i) == '}') { i++; return m; }
        while (true) {
            ws();
            String k = string();
            ws();
            expect(':');
            ws();
            m.put(k, value());
            ws();
            if (s.charAt(i) == ',') { i++; continue; }
            expect('}');
            return m;
        }
    }

    private List<Object> array() {
        List<Object> a = new ArrayList<>();
        i++;
        ws();
        if (s.charAt(i) == ']') { i++; return a; }
        while (true) {
            ws();
            a.add(value());
            ws();
            if (s.charAt(i) == ',') { i++; continue; }
            expect(']');
            return a;
        }
    }

    private void expect(char c) {
        if (i >= s.length() || s.charAt(i) != c) throw new IllegalArgumentException("expected '" + c + "' at " + i);
        i++;
    }

    private String string() {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true) {
            if (i >= s.length()) throw new IllegalArgumentException("unterminated string");
            char c = s.charAt(i++);
            if (c == '"') return b.toString();
            if (c < 0x20) throw new IllegalArgumentException("control character in a string at " + (i - 1));
            if (c != '\\') { b.append(c); continue; }
            if (i >= s.length()) throw new IllegalArgumentException("unterminated string");
            char e = s.charAt(i++);
            switch (e) {
                case '"': case '\\': case '/': b.append(e); break;
                case 'n': b.append('\n'); break;
                case 't': b.append('\t'); break;
                case 'r': b.append('\r'); break;
                case 'b': b.append('\b'); break;
                case 'f': b.append('\f'); break;
                case 'u': {
                    if (i + 4 > s.length()) throw new IllegalArgumentException("bad \\u escape at " + (i - 2));
                    int v = 0;
                    for (int k = 0; k < 4; k++) {
                        int d = Character.digit(s.charAt(i + k), 16);
                        if (d < 0 || s.charAt(i + k) > 'f') throw new IllegalArgumentException("bad \\u escape at " + (i - 2));
                        v = v * 16 + d;
                    }
                    b.append((char) v);
                    i += 4;
                    break;
                }
                default: throw new IllegalArgumentException("bad escape at " + (i - 2));
            }
        }
    }

    private boolean digits() {
        int start = i;
        while (i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9') i++;
        return i > start;
    }

    /** -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)? and nothing looser. An integer must fit 64 bits. */
    private Object number() {
        int start = i;
        boolean integer = true;
        if (i < s.length() && s.charAt(i) == '-') i++;
        int first = i;
        if (!digits() || (s.charAt(first) == '0' && i - first > 1)) throw new IllegalArgumentException("unexpected character at " + start);
        if (i < s.length() && s.charAt(i) == '.') {
            integer = false;
            i++;
            if (!digits()) throw new IllegalArgumentException("bad number at " + start);
        }
        if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
            integer = false;
            i++;
            if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
            if (!digits()) throw new IllegalArgumentException("bad number at " + start);
        }
        String n = s.substring(start, i);
        if (integer) return Long.parseLong(n);
        double d = Double.parseDouble(n);
        if (Double.isInfinite(d)) throw new IllegalArgumentException("number out of range at " + start);
        return d;
    }

    /**
     * Canonical JSON: keys sorted by code point, no whitespace, non-ASCII
     * written as itself, integers only. The audit hash chain, approval ids,
     * bundle versions and signatures depend on every port producing the same
     * bytes.
     */
    public static String canon(Object v) {
        StringBuilder b = new StringBuilder();
        canon(v, b);
        return b.toString();
    }

    static final java.util.Comparator<String> BY_CODE_POINT = (x, y) -> {
        int i = 0, j = 0;
        while (i < x.length() && j < y.length()) {
            int a = x.codePointAt(i), c = y.codePointAt(j);
            if (a != c) return Integer.compare(a, c);
            i += Character.charCount(a);
            j += Character.charCount(c);
        }
        return Integer.compare(x.length() - i, y.length() - j);
    };

    private static void canon(Object v, StringBuilder b) {
        if (v instanceof Map) {
            java.util.TreeMap<String, Object> sorted = new java.util.TreeMap<>(BY_CODE_POINT);
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) sorted.put(String.valueOf(e.getKey()), e.getValue());
            b.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : sorted.entrySet()) {
                if (!first) b.append(',');
                first = false;
                quote(e.getKey(), b);
                b.append(':');
                canon(e.getValue(), b);
            }
            b.append('}');
        } else if (v instanceof Iterable) {
            b.append('[');
            boolean first = true;
            for (Object x : (Iterable<?>) v) {
                if (!first) b.append(',');
                first = false;
                canon(x, b);
            }
            b.append(']');
        } else if (v instanceof Double || v instanceof Float) {
            throw new IllegalArgumentException("floating-point numbers have no canonical form here");
        } else {
            write(v, b);
        }
    }

    public static String write(Object v) {
        StringBuilder b = new StringBuilder();
        write(v, b);
        return b.toString();
    }

    private static void write(Object v, StringBuilder b) {
        if (v == null) {
            b.append("null");
        } else if (v instanceof String) {
            quote((String) v, b);
        } else if (v instanceof Number || v instanceof Boolean) {
            b.append(v);
        } else if (v instanceof Map) {
            b.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) b.append(',');
                first = false;
                quote(String.valueOf(e.getKey()), b);
                b.append(':');
                write(e.getValue(), b);
            }
            b.append('}');
        } else if (v instanceof Iterable) {
            b.append('[');
            boolean first = true;
            for (Object x : (Iterable<?>) v) {
                if (!first) b.append(',');
                first = false;
                write(x, b);
            }
            b.append(']');
        } else {
            throw new IllegalArgumentException("cannot write " + v.getClass().getName() + " as JSON");
        }
    }

    /**
     * JSON for people and for the wire, in the reference's layout.
     * {@code indent > 0}: one member per line, as Python's
     * {@code json.dumps(v, indent=n)}; otherwise one line with {@code ", "}
     * and {@code ": "}. {@code ascii}: everything outside ASCII is written as
     * {@code \}{@code uXXXX}, so the bytes are valid whatever the string
     * holds (a lone surrogate included).
     */
    public static String format(Object v, int indent, boolean ascii) {
        StringBuilder b = new StringBuilder();
        format(v, b, indent, 0, ascii);
        return b.toString();
    }

    /** Indented by two spaces, non-ASCII written as itself: what the command line prints. */
    public static String pretty(Object v) {
        return format(v, 2, false);
    }

    private static void newline(StringBuilder b, int indent, int depth) {
        if (indent > 0) b.append('\n').append(" ".repeat(indent * depth));
    }

    private static void format(Object v, StringBuilder b, int indent, int depth, boolean ascii) {
        if (v instanceof Map<?, ?> m) {
            if (m.isEmpty()) { b.append("{}"); return; }
            b.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) b.append(indent > 0 ? "," : ", ");
                first = false;
                newline(b, indent, depth + 1);
                quote(String.valueOf(e.getKey()), b, ascii);
                b.append(": ");
                format(e.getValue(), b, indent, depth + 1, ascii);
            }
            newline(b, indent, depth);
            b.append('}');
        } else if (v instanceof Iterable<?> it) {
            if (!it.iterator().hasNext()) { b.append("[]"); return; }
            b.append('[');
            boolean first = true;
            for (Object x : it) {
                if (!first) b.append(indent > 0 ? "," : ", ");
                first = false;
                newline(b, indent, depth + 1);
                format(x, b, indent, depth + 1, ascii);
            }
            newline(b, indent, depth);
            b.append(']');
        } else if (v instanceof String str) {
            quote(str, b, ascii);
        } else if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("not a JSON number: " + d);
            b.append(d);
        } else {
            write(v, b);
        }
    }

    private static void quote(String s, StringBuilder b) {
        quote(s, b, false);
    }

    private static void quote(String s, StringBuilder b, boolean ascii) {
        b.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                default:
                    if (c < 0x20 || (ascii && c > 0x7e)) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        b.append('"');
    }
}
