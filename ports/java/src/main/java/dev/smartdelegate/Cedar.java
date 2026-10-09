package dev.smartdelegate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Evaluator for Cedar's JSON policy form (the portable subset). A port of
 * src/sf_smartdelegate/cedar.py; what it must do is fixed by
 * spec/conformance/eval/cases.json, whose answers come from the real Cedar
 * engine. Anything outside the subset is refused when a policy is loaded.
 *
 * Values: Boolean, Long, String, {@link Entity}, {@link CSet}, and
 * {@code Map<String,Object>} for records.
 */
public final class Cedar {
    private Cedar() {}

    static final Pattern TYPE = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$");
    static final Set<String> BINARY = Set.of("==", "!=", "<", "<=", ">", ">=", "&&", "||", "+", "-", "*", "in", "contains", "containsAll", "containsAny");
    static final Set<String> UNARY = Set.of("!", "neg", "isEmpty");

    /** A policy condition could not be evaluated. The policy is skipped. */
    public static final class EvalError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        EvalError(String m) { super(m, null, false, false); }
    }

    /** The policy uses Cedar that is outside the portable subset. */
    public static final class Unsupported extends RuntimeException {
        private static final long serialVersionUID = 1L;
        Unsupported(String m) { super(m); }
    }

    public record Entity(String type, String id) {
        @Override public String toString() { return type + "::\"" + id + "\""; }
    }

    /** A Cedar set: unordered, no duplicates, any element types. */
    public static final class CSet {
        final Map<String, Object> items = new LinkedHashMap<>();
        CSet(Iterable<?> values) { for (Object v : values) items.put(key(v), v); }
    }

    /** An identity string for a value; equal values have equal keys. */
    @SuppressWarnings("unchecked")
    static String key(Object v) {
        if (v instanceof Boolean) return "b" + v;
        if (v instanceof Long) return "l" + v;
        if (v instanceof String s) return "s" + s.length() + ":" + s;
        if (v instanceof Entity e) return "e" + e.type().length() + ":" + e.type() + e.id().length() + ":" + e.id();
        if (v instanceof CSet s) {
            List<String> ks = new ArrayList<>(s.items.keySet());
            java.util.Collections.sort(ks);
            StringBuilder b = new StringBuilder("S" + ks.size() + "[");
            for (String k : ks) b.append(k.length()).append(':').append(k);
            return b.append(']').toString();
        }
        if (v instanceof Map) {
            TreeMap<String, Object> m = new TreeMap<>((Map<String, Object>) v);
            StringBuilder b = new StringBuilder("R" + m.size() + "{");
            for (Map.Entry<String, Object> e : m.entrySet()) {
                String k = key(e.getValue());
                b.append(e.getKey().length()).append(':').append(e.getKey()).append(k.length()).append(':').append(k);
            }
            return b.append('}').toString();
        }
        throw new EvalError("not a Cedar value");
    }

    static boolean validType(Object name) {
        return name instanceof String s && TYPE.matcher(s).matches();
    }

    /** JSON -> Cedar value. Lists are sets; {"__entity": {type, id}} is an entity reference. */
    @SuppressWarnings("unchecked")
    static Object fromJson(Object v) {
        if (v instanceof Boolean || v instanceof String || v instanceof Long) return v;
        if (v instanceof Number) throw new IllegalArgumentException("floating-point numbers are not Cedar values");
        if (v == null) throw new IllegalArgumentException("null is not a Cedar value");
        if (v instanceof List<?> l) {
            List<Object> out = new ArrayList<>();
            for (Object x : l) out.add(fromJson(x));
            return new CSet(out);
        }
        if (v instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) v;
            if (m.containsKey("__entity")) {
                Object e = m.get("__entity");
                if (m.size() != 1 || !(e instanceof Map<?, ?> em) || !validType(em.get("type")) || !(em.get("id") instanceof String))
                    throw new IllegalArgumentException("malformed __entity reference");
                return new Entity((String) em.get("type"), (String) em.get("id"));
            }
            if (m.containsKey("__extn")) throw new IllegalArgumentException("extension values (decimal, ip, datetime) are outside the portable subset");
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m.entrySet()) out.put(e.getKey(), fromJson(e.getValue()));
            return out;
        }
        throw new IllegalArgumentException("not a JSON value");
    }

    /** Entities: attributes and transitive ancestors. */
    public static final class Store {
        final Map<Entity, Map<String, Object>> attrs = new HashMap<>();
        final Map<Entity, List<Entity>> parents = new HashMap<>();
        private final Map<Entity, Set<Entity>> ancestors = new HashMap<>();

        Store() {}

        Store(List<Object> entitiesJson) { for (Object e : entitiesJson) add(e); }

        static Entity uid(Object u) {
            if (u instanceof Map<?, ?> m && m.containsKey("__entity")) u = m.get("__entity");
            if (!(u instanceof Map<?, ?> m) || !validType(m.get("type")) || !(m.get("id") instanceof String))
                throw new IllegalArgumentException("malformed entity uid");
            return new Entity((String) m.get("type"), (String) m.get("id"));
        }

        @SuppressWarnings("unchecked")
        Entity add(Object entity) {
            if (!(entity instanceof Map)) throw new IllegalArgumentException("entity must be an object");
            Map<String, Object> e = (Map<String, Object>) entity;
            Entity id = uid(e.get("uid"));
            if (attrs.containsKey(id)) throw new IllegalArgumentException("duplicate entity " + id);
            Object a = e.get("attrs");
            if (a != null && !(a instanceof Map)) throw new IllegalArgumentException(id + ": attrs must be an object");
            Map<String, Object> converted = new LinkedHashMap<>();
            if (a != null) for (Map.Entry<String, Object> x : ((Map<String, Object>) a).entrySet()) converted.put(x.getKey(), fromJson(x.getValue()));
            List<Entity> ps = new ArrayList<>();
            if (e.get("parents") instanceof List<?> l) for (Object p : l) ps.add(uid(p));
            attrs.put(id, converted);
            parents.put(id, ps);
            ancestors.clear();
            return id;
        }

        /** A store with request-scoped entities added. The base is not changed. */
        Store overlay(List<Object> extra) {
            Store s = new Store();
            s.attrs.putAll(attrs);
            s.parents.putAll(parents);
            for (Object e : extra) s.add(e);
            return s;
        }

        /**
         * A store in which {@code uid} has exactly these parents (and its stored
         * attributes, if any). Used for live group membership carried by a token.
         */
        Store withParents(Entity uid, List<Entity> newParents) {
            Store s = new Store();
            s.attrs.putAll(attrs);
            s.parents.putAll(parents);
            s.attrs.putIfAbsent(uid, new LinkedHashMap<>());
            s.parents.put(uid, new ArrayList<>(newParents));
            return s;
        }

        boolean contains(Entity e) { return attrs.containsKey(e); }

        Set<Entity> ancestors(Entity e) {
            Set<Entity> got = ancestors.get(e);
            if (got == null) {
                got = new HashSet<>();
                ArrayList<Entity> stack = new ArrayList<>(parents.getOrDefault(e, List.of()));
                while (!stack.isEmpty()) {
                    Entity p = stack.remove(stack.size() - 1);
                    if (got.add(p)) stack.addAll(parents.getOrDefault(p, List.of()));
                }
                ancestors.put(e, got);
            }
            return got;
        }

        boolean isIn(Entity child, Entity ancestor) { return child.equals(ancestor) || ancestors(child).contains(ancestor); }
    }

    // ---- loading: reject anything outside the subset ------------------------

    static Entity entityLit(Object e) {
        try {
            return Store.uid(e);
        } catch (IllegalArgumentException x) {
            throw new Unsupported("malformed entity in policy scope");
        }
    }

    @SuppressWarnings("unchecked")
    static void checkExpr(Object expr) {
        if (!(expr instanceof Map) || ((Map<?, ?>) expr).size() != 1) throw new Unsupported("malformed expression");
        Map.Entry<String, Object> only = ((Map<String, Object>) expr).entrySet().iterator().next();
        String op = only.getKey();
        Object arg = only.getValue();
        if (op.equals("Value")) {
            try { fromJson(arg); } catch (IllegalArgumentException x) { throw new Unsupported(x.getMessage()); }
            return;
        }
        if (op.equals("Var")) {
            if (!Set.of("principal", "action", "resource", "context").contains(arg)) throw new Unsupported("unknown variable");
            return;
        }
        if (op.equals("Set")) {
            if (!(arg instanceof List)) throw new Unsupported("malformed Set");
            for (Object x : (List<Object>) arg) checkExpr(x);
            return;
        }
        if (!(arg instanceof Map)) throw new Unsupported("`" + op + "` is outside the portable Cedar subset");
        Map<String, Object> a = (Map<String, Object>) arg;
        if (op.equals("Record")) {
            for (Object x : a.values()) checkExpr(x);
        } else if (BINARY.contains(op)) {
            checkExpr(a.get("left"));
            checkExpr(a.get("right"));
        } else if (UNARY.contains(op)) {
            checkExpr(a.get("arg"));
        } else if (op.equals(".") || op.equals("has")) {
            checkExpr(a.get("left"));
            if (!(a.get("attr") instanceof String)) throw new Unsupported("attribute name must be a string");
        } else if (op.equals("is")) {
            checkExpr(a.get("left"));
            if (!validType(a.get("entity_type"))) throw new Unsupported("malformed entity type in `is`");
            if (a.containsKey("in")) checkExpr(a.get("in"));
        } else if (op.equals("like")) {
            checkExpr(a.get("left"));
            if (!(a.get("pattern") instanceof List)) throw new Unsupported("malformed like pattern");
            for (Object part : (List<Object>) a.get("pattern"))
                if (!"Wildcard".equals(part) && !(part instanceof Map<?, ?> m && m.get("Literal") instanceof String)) throw new Unsupported("malformed like pattern");
        } else if (op.equals("if-then-else")) {
            checkExpr(a.get("if"));
            checkExpr(a.get("then"));
            checkExpr(a.get("else"));
        } else {
            throw new Unsupported("`" + op + "` is outside the portable Cedar subset");
        }
    }

    @SuppressWarnings("unchecked")
    static void checkScope(Object scope, String what) {
        if (!(scope instanceof Map)) throw new Unsupported("unsupported " + what + " scope");
        Map<String, Object> s = (Map<String, Object>) scope;
        if (s.containsKey("slot")) throw new Unsupported("policy templates are not supported");
        Object op = s.get("op");
        if ("All".equals(op)) return;
        if ("==".equals(op)) {
            entityLit(s.get("entity"));
        } else if ("in".equals(op)) {
            if (s.containsKey("entities")) {
                if (!what.equals("action") || !(s.get("entities") instanceof List)) throw new Unsupported(what + " scope cannot use a list");
                for (Object x : (List<Object>) s.get("entities")) entityLit(x);
            } else {
                entityLit(s.get("entity"));
            }
        } else if ("is".equals(op) && !what.equals("action")) {
            if (!validType(s.get("entity_type"))) throw new Unsupported("malformed entity type in scope");
            if (s.containsKey("in")) {
                if (!(s.get("in") instanceof Map<?, ?> in)) throw new Unsupported("malformed scope");
                entityLit(in.get("entity"));
            }
        } else {
            throw new Unsupported("unsupported " + what + " scope");
        }
    }

    public static final class Policy {
        final String id;
        final boolean permit;
        final Map<String, Object> principal, action, resource;
        final List<Map<String, Object>> conditions = new ArrayList<>();
        final Map<String, String> annotations = new LinkedHashMap<>();

        @SuppressWarnings("unchecked")
        Policy(String id, Object est) {
            if (!(est instanceof Map)) throw new Unsupported("malformed policy JSON");
            Map<String, Object> e = (Map<String, Object>) est;
            Object effect = e.get("effect");
            if (!"permit".equals(effect) && !"forbid".equals(effect)) throw new Unsupported("effect must be permit or forbid");
            for (String what : List.of("principal", "action", "resource")) checkScope(e.get(what), what);
            if (e.get("conditions") instanceof List<?> cs) {
                for (Object c : cs) {
                    if (!(c instanceof Map<?, ?> cm) || !("when".equals(cm.get("kind")) || "unless".equals(cm.get("kind")))) throw new Unsupported("condition must be when or unless");
                    checkExpr(cm.get("body"));
                    conditions.add((Map<String, Object>) c);
                }
            } else if (e.containsKey("conditions")) {
                throw new Unsupported("malformed policy JSON: conditions must be an array");
            }
            // as the reference: an object, or absent/empty
            Object ann = e.get("annotations");
            if (!(ann == null || ann instanceof Map || Boolean.FALSE.equals(ann) || Long.valueOf(0).equals(ann) || "".equals(ann) || (ann instanceof List<?> al && al.isEmpty())))
                throw new Unsupported("annotations must be an object");
            this.id = id;
            this.permit = "permit".equals(effect);
            this.principal = (Map<String, Object>) e.get("principal");
            this.action = (Map<String, Object>) e.get("action");
            this.resource = (Map<String, Object>) e.get("resource");
            if (e.get("annotations") instanceof Map<?, ?> an)
                for (Map.Entry<?, ?> x : an.entrySet()) annotations.put(String.valueOf(x.getKey()), x.getValue() == null ? "" : String.valueOf(x.getValue()));
        }
    }

    // ---- evaluation -----------------------------------------------------------

    public record Env(Entity principal, Entity action, Entity resource, Map<String, Object> context, Store store) {}

    static boolean bool(Object v, String what) {
        if (!(v instanceof Boolean b)) throw new EvalError(what + " must be a boolean");
        return b;
    }

    static long lng(Object v, String what) {
        if (!(v instanceof Long l)) throw new EvalError(what + " must be a long");
        return l;
    }

    static CSet set(Object v, String what) {
        if (!(v instanceof CSet s)) throw new EvalError(what + " must be a set");
        return s;
    }

    @SuppressWarnings("unchecked")
    static boolean like(String s, List<Object> pattern) {
        // classic wildcard match with backtracking to the last star, over code points
        int[] cp = s.codePoints().toArray();
        int[][] lit = new int[pattern.size()][];
        for (int k = 0; k < pattern.size(); k++)
            lit[k] = "Wildcard".equals(pattern.get(k)) ? null : ((String) ((Map<String, Object>) pattern.get(k)).get("Literal")).codePoints().toArray();
        // flatten multi-code-point literals
        List<int[]> flat = new ArrayList<>();
        for (int[] l : lit) {
            if (l == null) flat.add(null);
            else for (int c : l) flat.add(new int[] {c});
        }
        int i = 0, j = 0, star = -1, mark = -1;
        while (i < cp.length) {
            if (j < flat.size() && flat.get(j) != null && flat.get(j)[0] == cp[i]) { i++; j++; }
            else if (j < flat.size() && flat.get(j) == null) { star = j; mark = i; j++; }
            else if (star != -1) { j = star + 1; mark++; i = mark; }
            else return false;
        }
        while (j < flat.size() && flat.get(j) == null) j++;
        return j == flat.size();
    }

    static boolean in(Entity left, Object right, Env env) {
        if (right instanceof Entity e) return env.store().isIn(left, e);
        if (right instanceof CSet s) {
            for (Object x : s.items.values()) if (!(x instanceof Entity)) throw new EvalError("right of `in` must be an entity or a set of entities");
            for (Object x : s.items.values()) if (env.store().isIn(left, (Entity) x)) return true;
            return false;
        }
        throw new EvalError("right of `in` must be an entity or a set of entities");
    }

    @SuppressWarnings("unchecked")
    static Object evaluate(Object expr, Env env) {
        Map.Entry<String, Object> only = ((Map<String, Object>) expr).entrySet().iterator().next();
        String op = only.getKey();
        Object arg = only.getValue();
        switch (op) {
            case "Value": return fromJson(arg);
            case "Var":
                switch ((String) arg) {
                    case "principal": return env.principal();
                    case "action": return env.action();
                    case "resource": return env.resource();
                    default: return env.context();
                }
            case "Set": {
                List<Object> out = new ArrayList<>();
                for (Object x : (List<Object>) arg) out.add(evaluate(x, env));
                return new CSet(out);
            }
            default:
        }
        Map<String, Object> a = (Map<String, Object>) arg;
        switch (op) {
            case "Record": {
                Map<String, Object> out = new LinkedHashMap<>();
                for (Map.Entry<String, Object> e : a.entrySet()) out.put(e.getKey(), evaluate(e.getValue(), env));
                return out;
            }
            case "&&":
                if (!bool(evaluate(a.get("left"), env), "left of &&")) return false;
                return bool(evaluate(a.get("right"), env), "right of &&");
            case "||":
                if (bool(evaluate(a.get("left"), env), "left of ||")) return true;
                return bool(evaluate(a.get("right"), env), "right of ||");
            case "if-then-else":
                return evaluate(bool(evaluate(a.get("if"), env), "if condition") ? a.get("then") : a.get("else"), env);
            case "!": return !bool(evaluate(a.get("arg"), env), "operand of !");
            case "neg": {
                long x = lng(evaluate(a.get("arg"), env), "operand of -");
                if (x == Long.MIN_VALUE) throw new EvalError("integer overflow");
                return -x;
            }
            case "isEmpty": return set(evaluate(a.get("arg"), env), "isEmpty receiver").items.isEmpty();
            case ".": {
                Object left = evaluate(a.get("left"), env);
                String attr = (String) a.get("attr");
                Map<String, Object> rec;
                if (left instanceof Entity e) {
                    if (!env.store().contains(e)) throw new EvalError("entity " + e + " does not exist");
                    rec = env.store().attrs.get(e);
                } else if (left instanceof Map) {
                    rec = (Map<String, Object>) left;
                } else {
                    throw new EvalError("attribute access needs an entity or a record");
                }
                if (!rec.containsKey(attr)) throw new EvalError("no attribute `" + attr + "`");
                return rec.get(attr);
            }
            case "has": {
                Object left = evaluate(a.get("left"), env);
                if (left instanceof Entity e) return env.store().attrs.getOrDefault(e, Map.of()).containsKey((String) a.get("attr"));
                if (left instanceof Map) return ((Map<String, Object>) left).containsKey((String) a.get("attr"));
                throw new EvalError("`has` needs an entity or a record");
            }
            case "is": {
                Object left = evaluate(a.get("left"), env);
                if (!(left instanceof Entity e)) throw new EvalError("`is` needs an entity");
                if (!e.type().equals(a.get("entity_type"))) return false;
                return !a.containsKey("in") || in(e, evaluate(a.get("in"), env), env);
            }
            case "like": {
                Object left = evaluate(a.get("left"), env);
                if (!(left instanceof String s)) throw new EvalError("`like` needs a string");
                return like(s, (List<Object>) a.get("pattern"));
            }
            default:
        }
        Object left = evaluate(a.get("left"), env);
        Object right = evaluate(a.get("right"), env);
        try {
            switch (op) {
                case "==": return key(left).equals(key(right));
                case "!=": return !key(left).equals(key(right));
                case "<": return lng(left, "left of <") < lng(right, "right of <");
                case "<=": return lng(left, "left of <=") <= lng(right, "right of <=");
                case ">": return lng(left, "left of >") > lng(right, "right of >");
                case ">=": return lng(left, "left of >=") >= lng(right, "right of >=");
                case "+": return Math.addExact(lng(left, "left of +"), lng(right, "right of +"));
                case "-": return Math.subtractExact(lng(left, "left of -"), lng(right, "right of -"));
                case "*": return Math.multiplyExact(lng(left, "left of *"), lng(right, "right of *"));
                case "in":
                    if (!(left instanceof Entity e)) throw new EvalError("left of `in` must be an entity");
                    return in(e, right, env);
                case "contains": return set(left, "contains receiver").items.containsKey(key(right));
                case "containsAll": {
                    CSet l = set(left, "containsAll receiver"), r = set(right, "containsAll argument");
                    return l.items.keySet().containsAll(r.items.keySet());
                }
                case "containsAny": {
                    CSet l = set(left, "containsAny receiver"), r = set(right, "containsAny argument");
                    for (String k : r.items.keySet()) if (l.items.containsKey(k)) return true;
                    return false;
                }
                default: throw new EvalError("unsupported operator " + op);
            }
        } catch (ArithmeticException x) {
            throw new EvalError("integer overflow");
        }
    }

    @SuppressWarnings("unchecked")
    static boolean scope(Map<String, Object> scope, Entity who, Store store) {
        String op = (String) scope.get("op");
        if (op.equals("All")) return true;
        if (op.equals("==")) return who.equals(entityLit(scope.get("entity")));
        if (op.equals("in")) {
            if (scope.containsKey("entities")) {
                for (Object x : (List<Object>) scope.get("entities")) if (store.isIn(who, entityLit(x))) return true;
                return false;
            }
            return store.isIn(who, entityLit(scope.get("entity")));
        }
        if (!who.type().equals(scope.get("entity_type"))) return false;
        return !scope.containsKey("in") || store.isIn(who, entityLit(((Map<String, Object>) scope.get("in")).get("entity")));
    }

    /** True when the policy's scope and every condition hold. Throws EvalError. */
    static boolean applies(Policy p, Env env) {
        if (!(scope(p.principal, env.principal(), env.store()) && scope(p.action, env.action(), env.store()) && scope(p.resource, env.resource(), env.store()))) return false;
        for (Map<String, Object> c : p.conditions) {
            boolean v = bool(evaluate(c.get("body"), env), "`" + c.get("kind") + "` condition");
            if (v != "when".equals(c.get("kind"))) return false;
        }
        return true;
    }

    public record Result(boolean allow, List<String> reasons, List<String[]> errors) {}

    /** Cedar's authorization. A satisfied forbid denies; otherwise a satisfied permit allows; otherwise deny. */
    static Result isAuthorized(Map<String, Policy> policies, Env env) {
        List<String> permits = new ArrayList<>(), forbids = new ArrayList<>();
        List<String[]> errors = new ArrayList<>();
        for (String pid : new java.util.TreeSet<>(policies.keySet())) {
            Policy p = policies.get(pid);
            try {
                if (applies(p, env)) (p.permit ? permits : forbids).add(pid);
            } catch (EvalError e) {
                errors.add(new String[] {pid, e.getMessage()});
            }
        }
        if (!forbids.isEmpty()) return new Result(false, forbids, errors);
        if (!permits.isEmpty()) return new Result(true, permits, errors);
        return new Result(false, List.of(), errors);
    }
}
