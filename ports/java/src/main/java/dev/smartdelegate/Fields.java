package dev.smartdelegate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Applying a field mask and a row filter to JSON data. A port of
 * src/sf_smartdelegate/fields.py; the rules are stated there.
 */
final class Fields {
    private Fields() {}

    static final String REDACTED = "[REDACTED]";
    static final String ALLOW = "allow", DENY = "deny", REDACT = "redact";

    record Result(Object data, List<String> masked, int rowsDropped) {}

    static boolean hasChildren(Map<String, String> status, String path) {
        String a = path + ".", b = path + "[]";
        for (String k : status.keySet()) if (k.startsWith(a) || k.startsWith(b)) return true;
        return false;
    }

    static boolean container(Object v) {
        return v instanceof Map || v instanceof List;
    }

    private static final Object DROP = new Object();

    @SuppressWarnings("unchecked")
    static Object walkValue(Object v, String path, boolean inherit, Map<String, String> status, TreeSet<String> masked) {
        if (v instanceof Map) return walkObject((Map<String, Object>) v, path, inherit, status, masked);
        if (v instanceof List) {
            String p = path + "[]";
            String st = status.get(p);
            List<Object> out = new ArrayList<>();
            for (Object el : (List<Object>) v) {
                if (DENY.equals(st)) {
                    masked.add(p);
                } else if (REDACT.equals(st)) {
                    masked.add(p);
                    out.add(REDACTED);
                } else if (ALLOW.equals(st)) {
                    Object x = walkValue(el, p, true, status, masked);
                    if (x != DROP) out.add(x);
                } else if (container(el)) {
                    Object x = walkValue(el, p, inherit, status, masked);
                    if (x != DROP) out.add(x);
                } else if (inherit) {
                    out.add(el);
                } else {
                    masked.add(p);
                }
            }
            return out;
        }
        return inherit ? v : DROP;
    }

    static Map<String, Object> walkObject(Map<String, Object> m, String prefix, boolean inherit, Map<String, String> status, TreeSet<String> masked) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : m.entrySet()) {
            String k = e.getKey();
            Object v = e.getValue();
            String p = prefix.isEmpty() ? k : prefix + "." + k;
            String st = status.get(p);
            if (DENY.equals(st)) {
                masked.add(p);
            } else if (REDACT.equals(st)) {
                masked.add(p);
                out.put(k, REDACTED);
            } else if (ALLOW.equals(st)) {
                if (hasChildren(status, p)) {
                    Object x = walkValue(v, p, true, status, masked);
                    if (x != DROP) out.put(k, x);
                } else {
                    out.put(k, v);
                }
            } else if (inherit && !hasChildren(status, p)) {
                out.put(k, v);
            } else if (container(v) && hasChildren(status, p)) {
                Object x = walkValue(v, p, inherit, status, masked);
                if (x != DROP) out.put(k, x);
            } else if (inherit) {
                out.put(k, v);
            } else {
                masked.add(p);
            }
        }
        return out;
    }

    static boolean same(Object a, Object b) {
        return a == null ? b == null : a.equals(b);
    }

    @SuppressWarnings("unchecked")
    static boolean rowMatches(Object row, List<Object> rowFilter) {
        for (Object c : rowFilter) {
            if (!(c instanceof Map<?, ?> clause) || !(row instanceof Map)) return false;
            Object col = clause.get("column");
            Map<String, Object> r = (Map<String, Object>) row;
            if (!(col instanceof String) || !r.containsKey(col) || !same(r.get(col), clause.get("value"))) return false;
        }
        return true;
    }

    /** {@code data} is one record or a list of records. */
    @SuppressWarnings("unchecked")
    static Result apply(Object data, Map<String, String> status, List<Object> rowFilter) {
        TreeSet<String> masked = new TreeSet<>(Json.BY_CODE_POINT);
        int dropped = 0;
        Object out;
        if (data instanceof List) {
            List<Object> kept = new ArrayList<>();
            for (Object r : (List<Object>) data) {
                if (r instanceof Map && rowMatches(r, rowFilter)) kept.add(walkObject((Map<String, Object>) r, "", false, status, masked));
                else dropped++;
            }
            out = kept;
        } else if (data instanceof Map && rowMatches(data, rowFilter)) {
            out = walkObject((Map<String, Object>) data, "", false, status, masked);
        } else {
            // not matching the row filter, or a bare scalar with no field identity
            out = null;
            dropped = 1;
        }
        return new Result(out, new ArrayList<>(masked), dropped);
    }
}
