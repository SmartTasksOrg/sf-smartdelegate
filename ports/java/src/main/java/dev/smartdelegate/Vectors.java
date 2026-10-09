package dev.smartdelegate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Runner for the shared conformance vectors, for a bundle's own tests and for
 * the policy evaluation cases. A port of src/sf_smartdelegate/conformance.py.
 *
 * A case is a list of steps; each step names an operation, its input and a
 * partial expected result. {@code save} stores a value from a result and
 * {@code "$name"} in a later input is replaced by it.
 */
public final class Vectors {
    private Vectors() {}

    /** The outcome of a run: {@code results} holds {name, passed, failures} per case. */
    public static final class Report {
        public final List<Map<String, Object>> results = new ArrayList<>();

        public int total() {
            return results.size();
        }

        public int failed() {
            return (int) results.stream().filter(r -> !Boolean.TRUE.equals(r.get("passed"))).count();
        }
    }

    @SuppressWarnings("unchecked")
    static Object substitute(Object v, Map<String, Object> vars) {
        if (v instanceof String s && s.startsWith("$")) return vars.containsKey(s.substring(1)) ? vars.get(s.substring(1)) : v;
        if (v instanceof List) return ((List<Object>) v).stream().map(x -> substitute(x, vars)).collect(Collectors.toCollection(ArrayList::new));
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            ((Map<String, Object>) v).forEach((k, x) -> out.put(k, substitute(x, vars)));
            return out;
        }
        return v;
    }

    /** Equal as JSON values: 1 and 1.0 are the same number, true is not 1, key order does not matter. */
    static boolean same(Object a, Object b) {
        if (a == null || b == null) return a == b;
        if (a instanceof Number x && b instanceof Number y)
            return x instanceof Long && y instanceof Long ? x.longValue() == y.longValue() : x.doubleValue() == y.doubleValue();
        if (a instanceof Map<?, ?> x && b instanceof Map<?, ?> y) {
            if (x.size() != y.size()) return false;
            for (Map.Entry<?, ?> e : x.entrySet()) if (!y.containsKey(e.getKey()) || !same(e.getValue(), y.get(e.getKey()))) return false;
            return true;
        }
        if (a instanceof List<?> x && b instanceof List<?> y) {
            if (x.size() != y.size()) return false;
            for (int i = 0; i < x.size(); i++) if (!same(x.get(i), y.get(i))) return false;
            return true;
        }
        return a.equals(b);
    }

    /** Every key in {@code expect} must be present and equal in {@code actual}; objects recursively, everything else exactly. A mismatch, or null. */
    static String subset(Object expect, Object actual, String path) {
        if (expect instanceof Map<?, ?> e && actual instanceof Map<?, ?> a) {
            for (Map.Entry<?, ?> x : e.entrySet()) {
                String p = path.isEmpty() ? String.valueOf(x.getKey()) : path + "." + x.getKey();
                if (!a.containsKey(x.getKey())) {
                    if (x.getValue() == null) continue;
                    return p + ": missing, expected " + Json.format(x.getValue(), 0, true);
                }
                String m = subset(x.getValue(), a.get(x.getKey()), p);
                if (m != null) return m;
            }
            return null;
        }
        return same(expect, actual) ? null : path + ": expected " + Json.format(expect, 0, true) + ", got " + Json.format(actual, 0, true);
    }

    /** One case against {@code call(op, input) -> result}: {name, passed, failures: [{step, op, mismatch}]}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> runCase(BiFunction<String, Map<String, Object>, Map<String, Object>> call, Map<String, Object> c) {
        Map<String, Object> vars = new LinkedHashMap<>();
        List<Object> failures = new ArrayList<>();
        List<Object> steps = c.get("steps") instanceof List ? (List<Object>) c.get("steps") : List.of();
        for (int n = 0; n < steps.size(); n++) {
            Map<String, Object> step = steps.get(n) instanceof Map ? (Map<String, Object>) steps.get(n) : Map.of();
            String op = step.get("op") instanceof String s ? s : "";
            Object input = substitute(step.get("input"), vars);
            Map<String, Object> result = call.apply(op, input instanceof Map ? (Map<String, Object>) input : null);
            if (step.get("save") instanceof Map<?, ?> save) {
                for (Map.Entry<?, ?> e : save.entrySet()) {
                    Object cur = result;
                    for (String part : String.valueOf(e.getValue()).split("\\.")) cur = cur instanceof Map ? ((Map<String, Object>) cur).get(part) : null;
                    vars.put(String.valueOf(e.getKey()), cur);
                }
            }
            String m = subset(step.get("expect") != null ? step.get("expect") : Map.of(), result, "");
            if (m != null) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("step", (long) n);
                f.put("op", step.get("op"));
                f.put("mismatch", m);
                failures.add(f);
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", c.get("name"));
        out.put("passed", failures.isEmpty());
        out.put("failures", failures);
        return out;
    }

    private static List<Path> jsonFiles(Path dir) {
        if (!Files.isDirectory(dir)) return List.of();
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.getFileName().toString().endsWith(".json")).sorted(Comparator.comparing(p -> p.getFileName().toString())).collect(Collectors.toList());
        } catch (IOException e) {
            throw new EngineException("bundle_io", dir + ": " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> document(Path f) {
        try {
            String text = Files.readString(f, StandardCharsets.UTF_8);
            return Json.parseObject(text.startsWith("﻿") ? text.substring(1) : text);
        } catch (IOException | RuntimeException | StackOverflowError e) {
            throw new EngineException("invalid_input", f + ": " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> casesOf(Map<String, Object> doc) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (doc.get("cases") instanceof List<?> l) for (Object o : l) if (o instanceof Map) out.add((Map<String, Object>) o);
        return out;
    }

    private static void rm(Path dir) {
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (IOException ignored) {
            // a temporary directory that cannot be removed is not a test failure
        }
    }

    /** Every case of every file in {@code vectorsDir} against a fresh engine with its own state directory. */
    @SuppressWarnings("unchecked")
    public static Report runVectors(Path vectorsDir, Path bundleDir) {
        Report report = new Report();
        for (Path f : jsonFiles(vectorsDir)) {
            Map<String, Object> doc = document(f);
            for (Map<String, Object> c : casesOf(doc)) {
                Path state;
                try {
                    state = Files.createTempDirectory("smartdelegate-conf-");
                } catch (IOException e) {
                    throw new EngineException("state_io", String.valueOf(e.getMessage()));
                }
                try {
                    Map<String, Object> cfg = new LinkedHashMap<>();
                    cfg.put("bundle_dir", bundleDir.toString());
                    cfg.put("state_dir", state.toString());
                    cfg.put("allow_test_clock", true);
                    cfg.put("max_depth", 3L);
                    // a suite may add settings, e.g. an identity provider
                    if (doc.get("config") instanceof Map) cfg.putAll((Map<String, Object>) doc.get("config"));
                    try (Engine e = new Engine(cfg)) {
                        report.results.add(runCase(e::call, c));
                    }
                } finally {
                    rm(state);
                }
            }
        }
        return report;
    }

    /**
     * {@code <bundle>/tests/*.json} against a throwaway engine per case: no
     * state directory, no audit log, test clock on, caller-supplied chains trusted.
     */
    public static Report runBundleTests(Path bundleDir) {
        Report report = new Report();
        for (Path f : jsonFiles(bundleDir.resolve("tests"))) {
            for (Map<String, Object> c : casesOf(document(f))) {
                Map<String, Object> cfg = new LinkedHashMap<>();
                cfg.put("bundle_dir", bundleDir.toString());
                cfg.put("allow_test_clock", true);
                cfg.put("trust_caller_chain", true);
                cfg.put("audit", false);
                try (Engine e = new Engine(cfg)) {
                    report.results.add(runCase(e::call, c));
                }
            }
        }
        return report;
    }

    /** The policy evaluator against answers recorded from the real Cedar engine ({@code spec/conformance/eval/cases.json}). */
    @SuppressWarnings("unchecked")
    public static Report runEvalCases(Path casesFile) {
        Report report = new Report();
        Map<String, Object> doc = document(casesFile);
        try {
            Cedar.Store store = new Cedar.Store((List<Object>) doc.get("entities"));
            for (Map<String, Object> c : casesOf(doc)) {
                Map<String, Object> expect = (Map<String, Object>) c.get("expect");
                String failure = null;
                Map<String, Cedar.Policy> policies = new LinkedHashMap<>();
                boolean loaded = true;
                try {
                    for (Map.Entry<String, Object> e : ((Map<String, Object>) c.get("policies")).entrySet()) policies.put(e.getKey(), new Cedar.Policy(e.getKey(), e.getValue()));
                } catch (Cedar.Unsupported u) {
                    loaded = false;
                    if (!Boolean.TRUE.equals(expect.get("load_error"))) failure = "refused: " + u.getMessage();
                }
                if (loaded && Boolean.TRUE.equals(expect.get("load_error"))) {
                    failure = "should have been refused";
                } else if (loaded) {
                    Map<String, Object> r = (Map<String, Object>) c.get("request");
                    List<Object> pr = (List<Object>) r.get("principal"), rs = (List<Object>) r.get("resource");
                    Cedar.Env env = new Cedar.Env(new Cedar.Entity((String) pr.get(0), (String) pr.get(1)), new Cedar.Entity("Action", (String) r.get("action")),
                            new Cedar.Entity((String) rs.get(0), (String) rs.get(1)), (Map<String, Object>) Cedar.fromJson(r.get("context")), store);
                    Cedar.Result got = Cedar.isAuthorized(policies, env);
                    Map<String, Object> actual = new LinkedHashMap<>();
                    actual.put("decision", got.allow() ? "allow" : "deny");
                    actual.put("reasons", got.reasons());
                    actual.put("errors", got.errors().stream().map(e -> e[0]).sorted().collect(Collectors.toList()));
                    if (!actual.equals(expect)) failure = "got " + Json.write(actual) + ", Cedar says " + Json.write(expect);
                }
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("name", c.get("name"));
                out.put("passed", failure == null);
                out.put("failures", failure == null ? new ArrayList<>() : new ArrayList<>(List.of(failure)));
                report.results.add(out);
            }
        } catch (EngineException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new EngineException("invalid_input", casesFile + ": not a policy evaluation file (" + e + ")");
        }
        return report;
    }
}
