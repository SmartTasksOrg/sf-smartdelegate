package dev.smartdelegate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The test harness of the Java port. In order: the policy evaluation vectors,
 * the engine conformance vectors in-process, interoperability with the
 * reference implementation (tokens, bundles, audit logs), OIDC issuance, the
 * same conformance vectors through the REST client against a reference
 * daemon, checks of the client's typed helpers, and then the Java daemon and
 * command line ({@link DaemonChecks}).
 *
 *   java -cp build dev.smartdelegate.Conformance <repo root> <reference CLI...>
 *
 * The reference CLI is the Python package in <repo root>/src, e.g. (from
 * ports/java, or use ./run_conformance.sh which does all of this):
 *
 *   PYTHONPATH=../../src java -cp build dev.smartdelegate.Conformance ../.. python3 -m sf_smartdelegate
 */
public final class Conformance {
    static final String ADMIN = "admin-key-for-tests-0123456789";
    static final String PEP = "pep-key-for-tests-0123456789";

    static final class Daemon implements AutoCloseable {
        final Process proc;
        final Path dir;
        final String url;

        /** {@code extra}: the vector file's top-level "config", merged over the standard configuration; may be null. */
        Daemon(Path root, List<String> cli, Map<String, Object> extra) throws IOException {
            dir = Files.createTempDirectory("smartdelegate-java-");
            Map<String, Object> cfg = new LinkedHashMap<>();
            cfg.put("bundle_dir", root.resolve("spec").resolve("conformance").resolve("bundle").toString());
            cfg.put("state_dir", dir.resolve("state").toString());
            cfg.put("allow_test_clock", true);
            cfg.put("max_depth", 3L);
            cfg.put("admin_key", ADMIN);
            cfg.put("pep_key", PEP);
            if (extra != null) cfg.putAll(extra);
            Path config = dir.resolve("smartdelegate.json");
            Files.writeString(config, Json.write(cfg));
            List<String> cmd = new ArrayList<>(cli);
            cmd.addAll(List.of("serve", "--config", config.toString(), "--listen", "127.0.0.1:0"));
            proc = new ProcessBuilder(cmd).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
            BufferedReader err = new BufferedReader(new InputStreamReader(proc.getErrorStream(), StandardCharsets.UTF_8));
            String line = err.readLine();
            Matcher m = Pattern.compile("http://\\S+").matcher(line == null ? "" : line);
            if (!m.find()) {
                String rest = line + "\n" + err.lines().limit(20).collect(Collectors.joining("\n"));
                close();
                throw new IOException("daemon did not start: " + rest);
            }
            url = m.group();
        }

        @Override
        public void close() throws IOException {
            proc.destroyForcibly();
            try (Stream<Path> walk = Files.walk(dir)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    @SuppressWarnings("unchecked")
    static Object substitute(Object v, Map<String, Object> vars) {
        if (v instanceof String && ((String) v).startsWith("$")) {
            String name = ((String) v).substring(1);
            return vars.containsKey(name) ? vars.get(name) : v;
        }
        if (v instanceof List) return ((List<Object>) v).stream().map(x -> substitute(x, vars)).collect(Collectors.toCollection(ArrayList::new));
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            ((Map<String, Object>) v).forEach((k, x) -> out.put(k, substitute(x, vars)));
            return out;
        }
        return v;
    }

    /** Every key in expect must be present and equal in actual. Returns null or a mismatch. */
    @SuppressWarnings("unchecked")
    static String subset(Object expect, Object actual, String path) {
        if (expect instanceof Map && actual instanceof Map) {
            Map<String, Object> a = (Map<String, Object>) actual;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) expect).entrySet()) {
                String p = path.isEmpty() ? e.getKey() : path + "." + e.getKey();
                if (!a.containsKey(e.getKey())) {
                    if (e.getValue() == null) continue;
                    return p + ": missing, expected " + Json.write(e.getValue());
                }
                String m = subset(e.getValue(), a.get(e.getKey()), p);
                if (m != null) return m;
            }
            return null;
        }
        // Map.equals and List.equals compare deeply and ignore key order
        boolean same = expect == null ? actual == null : expect.equals(actual);
        return same ? null : path + ": expected " + Json.write(expect) + ", got " + Json.write(actual);
    }

    interface Caller {
        Map<String, Object> call(String op, Map<String, Object> input);
    }

    @SuppressWarnings("unchecked")
    static List<String> runCase(Caller caller, Map<String, Object> c) {
        Map<String, Object> vars = new LinkedHashMap<>();
        List<String> failures = new ArrayList<>();
        List<Object> steps = (List<Object>) c.get("steps");
        for (int i = 0; i < steps.size(); i++) {
            Map<String, Object> step = (Map<String, Object>) steps.get(i);
            Conformance.steps++;
            String op = (String) step.get("op");
            Map<String, Object> result = caller.call(op, (Map<String, Object>) substitute(step.get("input"), vars));
            Map<String, Object> save = (Map<String, Object>) step.get("save");
            if (save != null) {
                for (Map.Entry<String, Object> e : save.entrySet()) {
                    Object cur = result;
                    for (String part : ((String) e.getValue()).split("\\.")) cur = cur instanceof Map ? ((Map<String, Object>) cur).get(part) : null;
                    vars.put(e.getKey(), cur);
                }
            }
            Object expect = step.get("expect");
            String m = subset(expect == null ? Map.of() : expect, result, "");
            if (m != null) failures.add("step " + i + " (" + op + "): " + m);
        }
        return failures;
    }

    static int checks = 0;

    static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
        checks++;
    }

    /** Print how many checks ran since the last call. */
    static void passed(String label) {
        System.out.println(label + ": " + checks + " checks passed");
        checks = 0;
    }


    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> cases(Path root) throws IOException {
        List<Map<String, Object>> out = new ArrayList<>();
        List<Path> files;
        try (Stream<Path> s = Files.list(root.resolve("spec").resolve("conformance").resolve("vectors"))) {
            files = s.filter(p -> p.toString().endsWith(".json")).sorted().collect(Collectors.toList());
        }
        for (Path f : files) {
            Map<String, Object> doc = Json.parseObject(Files.readString(f));
            for (Object o : (List<Object>) doc.get("cases")) {
                @SuppressWarnings("unchecked") Map<String, Object> c = (Map<String, Object>) o;
                c.put("_suite", doc.get("suite"));
                // a suite may add settings, e.g. an identity provider
                c.put("_config", doc.get("config") instanceof Map ? doc.get("config") : null);
                out.add(c);
            }
        }
        return out;
    }

    static int failed = 0;

    static int steps = 0;

    static void report(String label, int total, int bad) {
        System.out.println(label + ": " + total + " cases" + (steps > 0 ? ", " + steps + " steps" : "") + ", " + bad + " failed");
        steps = 0;
        failed += bad;
    }

    /** The policy evaluator against answers recorded from the real Cedar engine. */
    @SuppressWarnings("unchecked")
    static void evalVectors(Path root) throws IOException {
        Map<String, Object> doc = Json.parseObject(Files.readString(root.resolve("spec/conformance/eval/cases.json")));
        Cedar.Store store = new Cedar.Store((List<Object>) doc.get("entities"));
        int total = 0, bad = 0;
        for (Object o : (List<Object>) doc.get("cases")) {
            Map<String, Object> c = (Map<String, Object>) o;
            Map<String, Object> expect = (Map<String, Object>) c.get("expect");
            total++;
            Map<String, Cedar.Policy> policies = new LinkedHashMap<>();
            try {
                for (Map.Entry<String, Object> e : ((Map<String, Object>) c.get("policies")).entrySet()) policies.put(e.getKey(), new Cedar.Policy(e.getKey(), e.getValue()));
            } catch (Cedar.Unsupported u) {
                if (!Boolean.TRUE.equals(expect.get("load_error"))) { bad++; System.out.println("FAIL eval: " + c.get("name") + ": refused: " + u.getMessage()); }
                continue;
            }
            if (Boolean.TRUE.equals(expect.get("load_error"))) { bad++; System.out.println("FAIL eval: " + c.get("name") + ": should have been refused"); continue; }
            Map<String, Object> r = (Map<String, Object>) c.get("request");
            List<Object> pr = (List<Object>) r.get("principal"), rs = (List<Object>) r.get("resource");
            Cedar.Env env = new Cedar.Env(new Cedar.Entity((String) pr.get(0), (String) pr.get(1)), new Cedar.Entity("Action", (String) r.get("action")),
                    new Cedar.Entity((String) rs.get(0), (String) rs.get(1)), (Map<String, Object>) Cedar.fromJson(r.get("context")), store);
            Cedar.Result got = Cedar.isAuthorized(policies, env);
            List<String> errs = got.errors().stream().map(e -> e[0]).sorted().collect(Collectors.toList());
            Map<String, Object> actual = new LinkedHashMap<>();
            actual.put("decision", got.allow() ? "allow" : "deny");
            actual.put("reasons", got.reasons());
            actual.put("errors", errs);
            if (!actual.equals(expect)) { bad++; System.out.println("FAIL eval: " + c.get("name") + ": got " + Json.write(actual) + ", Cedar says " + Json.write(expect)); }
        }
        report("java policy evaluation (against real Cedar's answers)", total, bad);
    }

    static Map<String, Object> config(Path root, Path state) {
        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("bundle_dir", root.resolve("spec").resolve("conformance").resolve("bundle").toString());
        cfg.put("state_dir", state.toString());
        cfg.put("allow_test_clock", true);
        cfg.put("max_depth", 3L);
        return cfg;
    }

    static void rm(Path dir) throws IOException {
        if (!Files.exists(dir)) return;
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    /** Run a command (the reference CLI): stdout and stderr together, stripped. Gives up after 120 seconds. */
    static String run(List<String> cmd) throws Exception {
        Path out = Files.createTempFile("smartdelegate-java-run-", ".txt");
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(out.toFile()).start();
            if (!p.waitFor(120, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
                throw new AssertionError("no answer within 120 s: " + cmd);
            }
            return new String(Files.readAllBytes(out), StandardCharsets.UTF_8).strip();
        } finally {
            Files.deleteIfExists(out);
        }
    }

    static List<String> with(List<String> cli, String... more) {
        List<String> cmd = new ArrayList<>(cli);
        cmd.addAll(List.of(more));
        return cmd;
    }

    static final List<String> BAD_ROLES = List.of(
            "[]", "{}", "{\"roles\": []}", "{\"role\": {}}", "not json",
            "{\"roles\": {\"r\": 1}}",
            "{\"roles\": {\"\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}}}}",
            "{\"roles\": {\"r\": {\"cap\": {}}}}",
            "{\"roles\": {\"r\": {\"members\": [], \"cap\": {}}}}",
            "{\"roles\": {\"r\": {\"members\": [\"support\"], \"cap\": {}}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"not a type\", \"id\": \"x\"}], \"cap\": {}}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": 1}], \"cap\": {}}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}]}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": null}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {\"action\": [\"read\"]}}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {\"actions\": [\"re*ad\"]}}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"max_tll\": 60}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"max_ttl\": 0}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"max_ttl\": true}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"max_ttl\": 1.5}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"max_ttl\": \"60\"}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"tasks\": []}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"tasks\": \"ticket-*\"}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"tasks\": [\"a*b\"]}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"agents\": [\"\"]}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"agents\": null}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"bindings\": []}}}",
            "{\"roles\": {\"r\": {\"members\": [{\"type\": \"Group\", \"id\": \"support\"}], \"cap\": {}, \"bindings\": null}}}");

    static void copyBundle(Path root, Path dest) throws IOException {
        Path src = root.resolve("spec/conformance/bundle");
        try (Stream<Path> walk = Files.walk(src)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                Path d = dest.resolve(src.relativize(p).toString());
                if (Files.isDirectory(p)) Files.createDirectories(d); else Files.copy(p, d);
            }
        }
    }

    /**
     * roles.json is validated when the bundle loads and is part of the bundle
     * version. Every malformed document must be refused with roles_parse by
     * Java and by the reference alike.
     */
    @SuppressWarnings("unchecked")
    static void rolesFile(Path root, List<String> cli) throws Exception {
        Path work = Files.createTempDirectory("smartdelegate-java-r-");
        try {
            Path b = work.resolve("bundle");
            copyBundle(root, b);
            Map<String, Object> cfg = new LinkedHashMap<>();
            cfg.put("bundle_dir", b.toString());
            Path cf = work.resolve("c.json");
            Files.writeString(cf, Json.write(cfg));
            String original;
            try (Engine e = new Engine(cfg)) {
                original = (String) e.call("info", new LinkedHashMap<>()).get("policy_version");
            }
            for (String bad : BAD_ROLES) {
                Files.writeString(b.resolve("roles.json"), bad);
                try {
                    new Engine(cfg).close();
                    check(false, "roles.json must be refused: " + bad);
                } catch (EngineException e) {
                    check(e.code().equals("roles_parse") && "DELEGATE-ROLES-PARSE".equals(((Map<String, Object>) e.toJson().get("error")).get("rule")), "roles.json " + bad + ": " + e.code());
                }
                String ref = run(with(cli, "info", "--config", cf.toString()));
                check(ref.contains("roles_parse"), "the reference refuses the same roles.json " + bad + ": " + ref);
            }
            // a valid edit changes the bundle version, identically in both engines
            Files.writeString(b.resolve("roles.json"), "{\"roles\": {\"r\": {\"members\": [{\"type\": \"User\", \"id\": \"dave\"}], \"cap\": {\"actions\": [\"read\"], \"resources\": [\"crm.customer/*\"]}, \"bindings\": {\"x\": 1.5}}}}");
            try (Engine e = new Engine(cfg)) {
                Map<String, Object> info = e.call("info", new LinkedHashMap<>());
                check(!original.equals(info.get("policy_version")), "roles.json is part of the bundle version");
                check(List.of("r").equals(info.get("roles")), "info lists the roles: " + Json.write(info.get("roles")));
                Map<String, Object> ref = Json.parseObject(run(with(cli, "info", "--config", cf.toString())));
                check(info.get("policy_version").equals(ref.get("policy_version")) && info.get("roles").equals(ref.get("roles")), "same version and roles as the reference after an edit");
            }
            // no roles.json: no roles, and naming one is unknown_role
            Files.delete(b.resolve("roles.json"));
            try (Engine e = new Engine(cfg)) {
                check(List.of().equals(e.call("info", new LinkedHashMap<>()).get("roles")), "a bundle without roles.json has no roles");
                Map<String, Object> r = e.call("issue_token", Json.parseObject("{\"user\":\"alice\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}"));
                Map<String, Object> err = (Map<String, Object>) r.get("error");
                check("unknown_role".equals(err.get("code")) && "DELEGATE-UNKNOWN-ROLE".equals(err.get("rule")), "unknown role: " + Json.write(r));
            }
            passed("java roles.json validation (same verdicts as the reference)");
        } finally {
            rm(work);
        }
    }

    static String code(Map<String, Object> r) {
        return r.get("error") instanceof Map<?, ?> e ? String.valueOf(e.get("code")) : null;
    }

    /** The error code with which an engine refuses to start on this config, or null if it starts. */
    static String startError(Map<String, Object> cfg) {
        try {
            new Engine(cfg).close();
            return null;
        } catch (EngineException e) {
            return e.code();
        }
        // anything else escapes and fails the harness: no other exception type is allowed
    }

    static Map<String, Object> m(String json) {
        return Json.parseObject(json);
    }

    static final String BASE_POLICY = "\"effect\":\"permit\",\"principal\":{\"op\":\"All\"},\"action\":{\"op\":\"All\"},\"resource\":{\"op\":\"All\"}";

    /** Policy JSON whose shape is wrong; each must be refused with policy_parse. */
    static final List<String> BAD_POLICIES = List.of(
            "{" + BASE_POLICY + ",\"conditions\":{}}",
            "{" + BASE_POLICY + ",\"conditions\":null}",
            "{" + BASE_POLICY + ",\"conditions\":\"when\"}",
            "{" + BASE_POLICY + ",\"conditions\":[\"when\"]}",
            "{" + BASE_POLICY + ",\"conditions\":[{\"kind\":\"when\",\"body\":{\"Set\":{}}}]}",
            "{" + BASE_POLICY + ",\"conditions\":[{\"kind\":\"when\",\"body\":{\"Set\":\"x\"}}]}",
            "{" + BASE_POLICY + ",\"conditions\":[{\"kind\":\"when\",\"body\":{\"Record\":[]}}]}",
            "{" + BASE_POLICY + ",\"conditions\":[{\"kind\":\"when\",\"body\":{\"Record\":\"x\"}}]}",
            "{" + BASE_POLICY + ",\"conditions\":[{\"kind\":\"when\",\"body\":{\"like\":{\"left\":{\"Value\":\"a\"},\"pattern\":\"a*\"}}}]}",
            "{" + BASE_POLICY + ",\"conditions\":[{\"kind\":\"when\",\"body\":{\"like\":{\"left\":{\"Value\":\"a\"},\"pattern\":{\"Literal\":\"a\"}}}}]}",
            "{\"effect\":\"permit\",\"principal\":{\"op\":\"All\"},\"action\":{\"op\":\"in\",\"entities\":{\"type\":\"Action\",\"id\":\"read\"}},\"resource\":{\"op\":\"All\"},\"conditions\":[]}",
            "{\"effect\":\"permit\",\"principal\":{\"op\":\"All\"},\"action\":{\"op\":\"in\",\"entities\":\"read\"},\"resource\":{\"op\":\"All\"},\"conditions\":[]}",
            "{" + BASE_POLICY + ",\"conditions\":[],\"annotations\":\"id\"}",
            "{" + BASE_POLICY + ",\"conditions\":[],\"annotations\":[\"id\"]}",
            "{" + BASE_POLICY + ",\"conditions\":[],\"annotations\":7}",
            "[]", "\"permit\"", "null");

    /** Child process of the signing-key race: wait for the starting gun, open an engine, print its public key and a token. */
    static void keyRaceChild(String[] args) throws Exception {
        long at = Long.parseLong(args[3]);
        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("bundle_dir", args[1]);
        cfg.put("state_dir", args[2]);
        while (System.currentTimeMillis() < at) Thread.onSpinWait();
        try (Engine e = new Engine(cfg)) {
            Map<String, Object> t = e.call("issue_token", m("{\"user\":\"alice\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}"));
            System.out.println(e.call("info", new LinkedHashMap<>()).get("public_key") + " " + t.get("token"));
        }
    }

    /** Run one operation in the reference CLI: `call <op> --input @file --config cfg`. */
    static Map<String, Object> refCall(List<String> cli, Path work, Path cfg, String op, Map<String, Object> input) throws Exception {
        Path in = work.resolve("in-" + System.nanoTime() + ".json");
        Files.writeString(in, Json.write(input));
        String out = run(with(cli, "call", op, "--input", "@" + in, "--config", cfg.toString()));
        try {
            return Json.parseObject(out);
        } catch (RuntimeException e) {
            throw new AssertionError("the reference did not answer " + op + " with JSON: " + out);
        }
    }

    /**
     * A verify-only engine with its own state directory enforces an ancestor
     * token's budget, because the budget travels in the `lim` claim: parent
     * 100.00, three children 60.00 each, 50 + 50 allowed, the third denied.
     * Java issues and the reference verifies, and the reverse.
     */
    @SuppressWarnings("unchecked")
    static void ancestorBudget(Path root, List<String> cli) throws Exception {
        Path work = Files.createTempDirectory("smartdelegate-java-b-");
        long now = 1700000000L;
        Map<String, Object> refund = m("{\"path\":\"billing.refund\",\"id\":\"r\"}");
        Map<String, Object> parentReq = m("{\"user\":\"alice\",\"agent\":\"support-bot\",\"now\":1700000000,\"cap\":{\"actions\":[\"create\"],\"resources\":[\"billing.refund/*\"],\"budget\":{\"EUR\":10000}}}");
        Map<String, Object> kidCap = m("{\"actions\":[\"create\"],\"resources\":[\"billing.refund/*\"],\"budget\":{\"EUR\":6000}}");
        Map<String, Object> spendCtx = m("{\"spend\":{\"currency\":\"EUR\",\"amount\":5000}}");
        try {
            // Java issues, verifiers with their own state decide
            Map<String, Object> icfg = config(root, work.resolve("java-issuer"));
            List<String> kids = new ArrayList<>();
            String pub;
            try (Engine issuer = new Engine(icfg)) {
                pub = (String) issuer.call("info", new LinkedHashMap<>()).get("public_key");
                Map<String, Object> parent = issuer.call("issue_token", parentReq);
                check(Boolean.TRUE.equals(parent.get("ok")), "java issues the parent: " + Json.write(parent));
                check(!((Map<String, Object>) issuer.call("inspect_token", obj("token", parent.get("token"), "now", now)).get("claims")).containsKey("lim"), "a root token has no lim");
                for (int k = 0; k < 3; k++) {
                    Map<String, Object> kid = issuer.call("exchange_token", obj("subject_token", parent.get("token"), "actor", "refund-helper", "ttl", 300L, "now", now, "cap", kidCap));
                    check(Boolean.TRUE.equals(kid.get("ok")), "java issues a child: " + Json.write(kid));
                    kids.add((String) kid.get("token"));
                }
                Map<String, Object> claims = (Map<String, Object>) issuer.call("inspect_token", obj("token", kids.get(0), "now", now)).get("claims");
                check(obj(parent.get("token_id"), obj("EUR", 10000L)).equals(claims.get("lim")), "the child carries its parent's budget in lim: " + Json.write(claims.get("lim")));
                // a grandchild carries both; a child of a token without a budget carries none
                Map<String, Object> grand = issuer.call("exchange_token", obj("subject_token", kids.get(0), "actor", "summarizer", "ttl", 60L, "now", now));
                Map<String, Object> gl = (Map<String, Object>) ((Map<String, Object>) issuer.call("inspect_token", obj("token", grand.get("token"), "now", now)).get("claims")).get("lim");
                check(gl != null && gl.size() == 2 && obj("EUR", 10000L).equals(gl.get(parent.get("token_id"))) && gl.containsValue(obj("EUR", 6000L)), "a grandchild carries every ancestor's budget: " + Json.write(grand) + " " + Json.write(gl));
                Map<String, Object> plain = issuer.call("issue_token", m("{\"user\":\"bob\",\"agent\":\"support-bot\",\"role\":\"auditor\",\"now\":1700000000}"));
                Map<String, Object> pk = issuer.call("exchange_token", obj("subject_token", plain.get("token"), "actor", "refund-helper", "ttl", 60L, "now", now));
                check(Boolean.TRUE.equals(pk.get("ok")) && !((Map<String, Object>) issuer.call("inspect_token", obj("token", pk.get("token"), "now", now)).get("claims")).containsKey("lim"), "no lim when no ancestor has a budget: " + Json.write(pk));

                // a forged or malformed lim is not a token
                Tokens.Keys signer = new Tokens.Keys(Files.readString(work.resolve("java-issuer").resolve("signing_key.pk8.b64")), List.of());
                check(Boolean.TRUE.equals(issuer.call("inspect_token", obj("token", signer.sign(claims), "now", now)).get("valid")), "the re-signed child is valid");
                for (Object bad : new Object[] {"x", List.of(), obj("a", 5L), obj("a", obj("EUR", -1L)), obj("a", obj("EUR", "9")), obj("a", obj("EUR", true)), obj("a", obj("EUR", 1.5)), obj("a", List.of()), obj("a", null), null, 7L}) {
                    Map<String, Object> c2 = new LinkedHashMap<>(claims);
                    c2.put("lim", bad);
                    Map<String, Object> r = issuer.call("inspect_token", obj("token", signer.sign(c2), "now", now));
                    check(Boolean.FALSE.equals(r.get("valid")) && "token_invalid".equals(r.get("reason")), "lim " + Json.write(bad) + " is token_invalid: " + Json.write(r));
                    Map<String, Object> d = issuer.call("authorize", obj("token", signer.sign(c2), "action", "create", "resource", refund, "now", now, "context", spendCtx));
                    check("deny".equals(d.get("effect")) && "token_invalid".equals(d.get("reason")), "and is denied: " + Json.write(d));
                }
                // lim cannot raise a limit the engine itself recorded: its own state wins
                for (int k = 1; k < 3; k++)
                    check("allow".equals(issuer.call("authorize", obj("token", kids.get(k), "action", "create", "resource", refund, "now", now, "context", spendCtx)).get("effect")), "the issuer allows 50.00 on a child");
                Map<String, Object> c3 = new LinkedHashMap<>(claims);
                c3.put("lim", obj(parent.get("token_id"), obj("EUR", 99999999L)));
                Map<String, Object> d = issuer.call("authorize", obj("token", signer.sign(c3), "action", "create", "resource", refund, "now", now, "context", spendCtx));
                check("deny".equals(d.get("effect")) && "budget_exceeded".equals(d.get("reason")), "the issuer's own record of an ancestor's limit wins over a larger lim: " + Json.write(d));
            }
            for (String who : List.of("java", "reference")) {
                Map<String, Object> vcfg = config(root, work.resolve("verifier-" + who));
                vcfg.put("verify_only", true);
                vcfg.put("trusted_keys", List.of(pub));
                Path vc = work.resolve("verifier-" + who + ".json");
                Files.writeString(vc, Json.write(vcfg));
                List<Map<String, Object>> got = new ArrayList<>();
                if (who.equals("java")) {
                    try (Engine v = new Engine(vcfg)) {
                        for (String k : kids) got.add(v.call("authorize", obj("token", k, "action", "create", "resource", refund, "now", now, "context", spendCtx)));
                    }
                } else {
                    for (String k : kids) got.add(refCall(cli, work, vc, "authorize", obj("token", k, "action", "create", "resource", refund, "now", now, "context", spendCtx)));
                }
                check("allow".equals(got.get(0).get("effect")) && "allow".equals(got.get(1).get("effect")), "a " + who + " verifier with its own state allows 50 + 50 of java's tokens: " + Json.write(got.get(0)) + Json.write(got.get(1)));
                check("deny".equals(got.get(2).get("effect")) && "budget_exceeded".equals(got.get(2).get("reason")), "and denies the third: the parent's 100.00 is spent: " + Json.write(got.get(2)));
            }

            // the reference issues, a Java verifier with its own state decides
            Map<String, Object> rcfg = config(root, work.resolve("ref-issuer"));
            Path rc = work.resolve("ref-issuer.json");
            Files.writeString(rc, Json.write(rcfg));
            Map<String, Object> rparent = refCall(cli, work, rc, "issue_token", parentReq);
            check(Boolean.TRUE.equals(rparent.get("ok")), "the reference issues the parent: " + Json.write(rparent));
            List<String> rkids = new ArrayList<>();
            for (int k = 0; k < 3; k++)
                rkids.add((String) refCall(cli, work, rc, "exchange_token", obj("subject_token", rparent.get("token"), "actor", "refund-helper", "ttl", 300L, "now", now, "cap", kidCap)).get("token"));
            Map<String, Object> jv = config(root, work.resolve("java-verifier"));
            jv.put("verify_only", true);
            jv.put("trusted_keys", List.of(Files.readString(work.resolve("ref-issuer").resolve("signing_key.pub.b64")).strip()));
            try (Engine v = new Engine(jv)) {
                Map<String, Object> claims = (Map<String, Object>) v.call("inspect_token", obj("token", rkids.get(0), "now", now)).get("claims");
                check(claims != null && obj(rparent.get("token_id"), obj("EUR", 10000L)).equals(claims.get("lim")), "the reference's child carries the same lim: " + Json.write(claims));
                Map<String, Object> a = v.call("authorize", obj("token", rkids.get(0), "action", "create", "resource", refund, "now", now, "context", spendCtx));
                Map<String, Object> b = v.call("authorize", obj("token", rkids.get(1), "action", "create", "resource", refund, "now", now, "context", spendCtx));
                Map<String, Object> c = v.call("authorize", obj("token", rkids.get(2), "action", "create", "resource", refund, "now", now, "context", spendCtx));
                check("allow".equals(a.get("effect")) && "allow".equals(b.get("effect")), "a java verifier with its own state allows 50 + 50 of the reference's tokens: " + Json.write(a) + Json.write(b));
                check("deny".equals(c.get("effect")) && "budget_exceeded".equals(c.get("reason")), "and denies the third: " + Json.write(c));
            }
            passed("java ancestor budgets across engines (lim claim, both directions)");
        } finally {
            rm(work);
        }
    }

    /**
     * Approval ids are byte-identical across ports, and bound to the
     * resource attributes of the request: the same token and request give the
     * same id in Java and in the reference, with and without attrs.
     */
    @SuppressWarnings("unchecked")
    static void approvalIds(Path root, List<String> cli) throws Exception {
        Path work = Files.createTempDirectory("smartdelegate-java-a-");
        long now = 1700000000L;
        try {
            Map<String, Object> jcfg = config(root, work.resolve("java"));
            try (Engine e = new Engine(jcfg)) {
                String token = (String) e.call("issue_token", m("{\"user\":\"alice\",\"agent\":\"support-bot\",\"tenant\":\"acme\",\"now\":1700000000,\"cap\":{\"actions\":[\"create\"],\"resources\":[\"billing.refund/*\"],\"budget\":{\"EUR\":40000}}}")).get("token");
                Map<String, Object> rcfg = config(root, work.resolve("ref"));
                rcfg.put("verify_only", true);
                rcfg.put("trusted_keys", List.of(e.call("info", new LinkedHashMap<>()).get("public_key")));
                Path rc = work.resolve("ref.json");
                Files.writeString(rc, Json.write(rcfg));
                Map<String, Object> ctx = m("{\"spend\":{\"currency\":\"EUR\",\"amount\":15000},\"note\":\"\u00e9 \u2713\"}");
                String full = "{\"customer_owner\":\"carol\",\"note\":\"\u00e9 \u2713 \ud83d\ude00 \u2028\",\"n\":7,\"neg\":-9007199254740993,\"meta\":{\"b\":1,\"a\":{\"z\":\"y\",\"\u00e9\":true}}}";
                String shuffled = "{\"meta\":{\"a\":{\"\u00e9\":true,\"z\":\"y\"},\"b\":1},\"neg\":-9007199254740993,\"n\":7,\"note\":\"\u00e9 \u2713 \ud83d\ude00 \u2028\",\"customer_owner\":\"carol\"}";
                String other = full.replace("\"n\":7", "\"n\":8");
                Map<String, String> ids = new LinkedHashMap<>();
                for (String attrs : new String[] {null, "{}", full, shuffled, other, "{\"customer_owner\":\"carol\"}"}) {
                    Map<String, Object> res = m("{\"path\":\"billing.refund\",\"id\":\"r-7\"}");
                    if (attrs != null) res.put("attrs", m(attrs));
                    Map<String, Object> req = obj("token", token, "action", "create", "resource", res, "context", ctx, "now", now, "dry_run", true);
                    Map<String, Object> j = e.call("authorize", req);
                    Map<String, Object> r = refCall(cli, work, rc, "authorize", req);
                    String jid = j.get("approval") instanceof Map<?, ?> a ? (String) a.get("id") : null;
                    String rid = r.get("approval") instanceof Map<?, ?> a ? (String) a.get("id") : null;
                    check("approval_required".equals(j.get("reason")) && jid != null && jid.matches("[0-9a-f]{24}"), "java asks for approval (attrs " + attrs + "): " + Json.write(j));
                    check(jid.equals(rid), "java and the reference compute the same approval id (attrs " + attrs + "): " + jid + " / " + Json.write(r));
                    ids.put(String.valueOf(attrs), jid);
                }
                check(ids.get("null").equals(ids.get("{}")), "absent attrs and {} are the same request");
                check(ids.get(full).equals(ids.get(shuffled)), "key order does not matter");
                check(new java.util.HashSet<>(ids.values()).size() == 4, "requests that differ in an attribute have different ids: " + ids);
                // an explicit null is the same as absent, as in the reference
                Map<String, Object> res = m("{\"path\":\"billing.refund\",\"id\":\"r-7\"}");
                res.put("attrs", null);
                Map<String, Object> req = obj("token", token, "action", "create", "resource", res, "context", ctx, "now", now, "dry_run", true);
                Map<String, Object> j = e.call("authorize", req), r = refCall(cli, work, rc, "authorize", req);
                check(j.get("approval") instanceof Map<?, ?> a && ids.get("null").equals(a.get("id")) && a.equals(r.get("approval")), "attrs null is the same as absent, in both: " + Json.write(j) + Json.write(r));
            }
            passed("java approval ids (same as the reference, bound to resource.attrs)");
        } finally {
            rm(work);
        }
    }

    /** The "Strictness (0.3)" section of spec/PORTING.md, bullet by bullet. */
    @SuppressWarnings("unchecked")
    static void strictness(Path root, List<String> cli) throws Exception {
        Path work = Files.createTempDirectory("smartdelegate-java-s-");
        String bundleDir = root.resolve("spec/conformance/bundle").toString();
        Map<String, Object> customer = m("{\"path\":\"crm.customer\",\"id\":\"c-1\"}");
        try {
            // -- audit lines end at "\n" and nowhere else
            String odd = "t x y\u0085z";
            Map<String, Object> cfg = config(root, work.resolve("audit"));
            Map<String, Object> issue = m("{\"user\":\"alice\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}");
            issue.put("task", odd);
            String token;
            try (Engine e = new Engine(cfg)) {
                Map<String, Object> t = e.call("issue_token", issue);
                check(Boolean.TRUE.equals(t.get("ok")), "a task with U+2028 is issued: " + Json.write(t));
                token = (String) t.get("token");
                String log = Files.readString(work.resolve("audit").resolve("audit.jsonl"));
                check(log.contains(odd) && log.chars().filter(ch -> ch == '\n').count() == 1, "U+2028, U+2029 and U+0085 are written as themselves, on one line");
                Map<String, Object> v = e.call("audit_verify", new LinkedHashMap<>());
                check(Boolean.TRUE.equals(v.get("ok")) && Long.valueOf(1).equals(v.get("records")), "the log with U+2028 verifies: " + Json.write(v));
                List<Object> tail = (List<Object>) e.call("audit_tail", m("{\"n\":5}")).get("records");
                check(tail.size() == 1 && odd.equals(((Map<String, Object>) tail.get(0)).get("task")), "audit_tail returns the record whole: " + Json.write(tail));
            }
            try (Engine e2 = new Engine(cfg)) {     // a second engine on the same state directory
                Map<String, Object> d = e2.call("authorize", obj("token", token, "action", "read", "resource", customer));
                check("allow".equals(d.get("effect")) && odd.equals(((Map<String, Object>) d.get("principal")).get("task")), "a second engine opens the log and decides: " + Json.write(d));
                Map<String, Object> v = e2.call("audit_verify", new LinkedHashMap<>());
                check(Boolean.TRUE.equals(v.get("ok")) && Long.valueOf(2).equals(v.get("records")), "and appends to the same chain: " + Json.write(v));
                List<Object> tail = (List<Object>) e2.call("audit_tail", m("{\"n\":1}")).get("records");
                check(tail.size() == 1 && "decision".equals(((Map<String, Object>) tail.get(0)).get("event")), "audit_tail n=1 is the last record");
            }
            Path ac = work.resolve("audit.json");
            Files.writeString(ac, Json.write(cfg));
            Map<String, Object> rv = m(run(with(cli, "audit", "verify", "--config", ac.toString())));
            check(Boolean.TRUE.equals(rv.get("ok")) && Long.valueOf(2).equals(rv.get("records")), "the reference verifies java's log with U+2028: " + Json.write(rv));
            // and the reverse: a record with U+2028 written by the reference
            Map<String, Object> rcfg = config(root, work.resolve("ref-audit"));
            Path rcf = work.resolve("ref-audit.json"), in = work.resolve("issue.json");
            Files.writeString(rcf, Json.write(rcfg));
            Files.writeString(in, Json.write(issue));
            Map<String, Object> rt = m(run(with(cli, "call", "issue_token", "--input", "@" + in, "--config", rcf.toString())));
            check(Boolean.TRUE.equals(rt.get("ok")), "the reference issues the same token: " + Json.write(rt));
            Map<String, Object> jv = Audit.verify(work.resolve("ref-audit").resolve("audit.jsonl"));
            check(Boolean.TRUE.equals(jv.get("ok")) && Long.valueOf(1).equals(jv.get("records")), "java verifies the reference's log with U+2028: " + Json.write(jv));
            List<Object> rtail = Audit.tail(work.resolve("ref-audit").resolve("audit.jsonl"), 5);
            check(rtail.size() == 1 && odd.equals(((Map<String, Object>) rtail.get(0)).get("task")), "java tails the reference's log with U+2028");
            passed("java strictness: audit lines end at \\n only");

            // -- base64url is strict; `anc` is an array of strings
            Map<String, Object> tcfg = config(root, work.resolve("tok"));
            try (Engine e = new Engine(tcfg)) {
                String good = (String) e.call("issue_token", m("{\"user\":\"alice\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}")).get("token");
                check("allow".equals(e.call("authorize", obj("token", good, "action", "read", "resource", customer)).get("effect")), "the untouched token is accepted");
                String[] p = good.split("\\.");
                List<String> spellings = new ArrayList<>(List.of(good + "!!!!", good + "=", good + "==", good + "\n", good + " ", " " + good, good + "A!",
                        p[0] + "." + p[1].substring(0, 8) + "!" + p[1].substring(8) + "." + p[2],
                        p[0] + "." + p[1].substring(0, 8) + "\n" + p[1].substring(8) + "." + p[2],
                        p[0] + "." + p[1].substring(0, 8) + " " + p[1].substring(8) + "." + p[2],
                        p[0].substring(0, 4) + "$$" + p[0].substring(4) + "." + p[1] + "." + p[2],
                        p[0] + "=." + p[1] + "." + p[2],
                        p[0] + "." + p[1] + "=." + p[2],
                        p[0] + "." + p[1] + "." + p[2].substring(0, 10) + "*" + p[2].substring(10),
                        p[0] + "." + p[1] + "." + p[2].replace('-', '+').replace('_', '/') + "+/"));
                for (String bad : spellings) {
                    Map<String, Object> d = e.call("authorize", obj("token", bad, "action", "read", "resource", customer));
                    check("deny".equals(d.get("effect")) && "token_invalid".equals(d.get("reason")) && "DELEGATE-TOKEN-INVALID".equals(d.get("rule")), "a respelt token is token_invalid: " + Json.write(d));
                    Map<String, Object> i = e.call("inspect_token", obj("token", bad));
                    check(Boolean.FALSE.equals(i.get("valid")) && "token_invalid".equals(i.get("reason")), "inspect_token agrees: " + Json.write(i));
                    check("token_invalid".equals(code(e.call("exchange_token", obj("subject_token", bad, "actor", "refund-helper")))), "exchange_token agrees");
                }
                // well-signed tokens whose `anc` has the wrong shape
                Map<String, Object> claims = (Map<String, Object>) e.call("inspect_token", obj("token", good)).get("claims");
                Tokens.Keys signer = new Tokens.Keys(Files.readString(work.resolve("tok").resolve("signing_key.pk8.b64")), List.of());
                check("allow".equals(e.call("authorize", obj("token", signer.sign(claims), "action", "read", "resource", customer)).get("effect")), "a token re-signed with the engine's key is accepted");
                for (Object anc : new Object[] {"abc", "", List.of(1L), List.of("a", List.of()), obj("a", "b"), 7L, true}) {
                    Map<String, Object> c2 = new LinkedHashMap<>(claims);
                    c2.put("anc", anc);
                    Map<String, Object> d = e.call("authorize", obj("token", signer.sign(c2), "action", "read", "resource", customer));
                    check("deny".equals(d.get("effect")) && "token_invalid".equals(d.get("reason")), "anc " + Json.write(anc) + " is token_invalid: " + Json.write(d));
                }
            }
            passed("java strictness: strict base64url, anc is an array of strings");

            // -- entity type names match in full
            check(Cedar.validType("User") && Cedar.validType("A::b_1::C") && !Cedar.validType("User\n") && !Cedar.validType("\nUser") && !Cedar.validType("A::B\n")
                    && !Cedar.validType("A::") && !Cedar.validType("A:B") && !Cedar.validType("1A") && !Cedar.validType("") && !Cedar.validType("A b"), "entity type names match in full");
            Path eb = work.resolve("ent-bundle");
            Map<String, Object> ecfg = obj("bundle_dir", eb.toString());
            Path ecf = work.resolve("ent.json");
            Files.writeString(ecf, Json.write(ecfg));
            for (String ents : List.of("[{\"uid\":{\"type\":\"User\\n\",\"id\":\"zed\"},\"attrs\":{},\"parents\":[]}]",
                    "[{\"uid\":{\"type\":\"User\",\"id\":\"zed\"},\"attrs\":{},\"parents\":[{\"type\":\"Group\\n\",\"id\":\"g\"}]}]",
                    "{}", "{\"entities\":[]}", "[1]", "[\"User::zed\"]", "[[]]", "[null]", "\"x\"", "7", "null")) {
                rm(eb);
                copyBundle(root, eb);
                Files.writeString(eb.resolve("entities.json"), ents);
                check("entities_parse".equals(startError(ecfg)), "entities.json " + ents + " is entities_parse: " + startError(ecfg));
                String ref = run(with(cli, "info", "--config", ecf.toString()));
                check(ref.contains("entities_parse"), "the reference agrees on entities.json " + ents + ": " + ref);
            }
            try (Engine e = new Engine(config(root, work.resolve("ent-state")))) {
                String t = (String) e.call("issue_token", m("{\"user\":\"alice\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}")).get("token");
                Map<String, Object> r = e.call("authorize", obj("token", t, "action", "read", "resource", customer, "context", obj("who", obj("__entity", obj("type", "User\n", "id", "alice")))));
                check("invalid_context".equals(code(r)), "an entity reference with a trailing newline in its type is refused: " + Json.write(r));
                r = e.call("issue_token", m("{\"user\":\"alice\",\"agent\":\"support-bot\",\"cap\":{\"actions\":[\"read\"],\"resources\":[\"crm.customer/*\"]},\"groups\":[{\"type\":\"Group\\n\",\"id\":\"support\"}]}"));
                check("delegation_denied".equals(code(r)), "a group whose type has a trailing newline is not the group: " + Json.write(r));
            }
            passed("java strictness: entity type names, entities.json is a list of objects");

            // -- policy JSON shapes are checked at load
            Path pb = work.resolve("pol-bundle");
            Files.createDirectories(pb);
            Map<String, Object> pcfg = obj("bundle_dir", pb.toString());
            Path pcf = work.resolve("pol.json");
            Files.writeString(pcf, Json.write(pcfg));
            Files.writeString(pb.resolve("policies.json"), "{\"policies\":{\"p\":{" + BASE_POLICY + ",\"conditions\":[{\"kind\":\"when\",\"body\":{\"like\":{\"left\":{\"Value\":\"a\"},\"pattern\":[{\"Literal\":\"a\"},\"Wildcard\"]}}}],\"annotations\":{\"id\":\"p\"}}}}");
            check(startError(pcfg) == null, "a well-formed policy loads: " + startError(pcfg));
            for (String bad : BAD_POLICIES) {
                Files.writeString(pb.resolve("policies.json"), "{\"policies\":{\"p\":" + bad + "}}");
                check("policy_parse".equals(startError(pcfg)), "policy " + bad + " is policy_parse: " + startError(pcfg));
                String ref = run(with(cli, "info", "--config", pcf.toString()));
                check(ref.contains("policy_parse"), "the reference agrees on policy " + bad + ": " + ref);
            }
            for (String doc : List.of("[]", "{\"policies\":[]}", "{}", "{\"policies\":\"x\"}", "not json")) {
                Files.writeString(pb.resolve("policies.json"), doc);
                check("policy_parse".equals(startError(pcfg)), "policies.json " + doc + " is policy_parse: " + startError(pcfg));
            }
            passed("java strictness: policy JSON shapes");

            // -- files that are not UTF-8
            byte[] notUtf8 = {'{', '"', 'a', '"', ':', '"', (byte) 0xff, (byte) 0xfe, (byte) 0xc3, '"', '}', '\n'};
            Map<String, Object> ucfg = config(root, work.resolve("utf"));
            try (Engine e = new Engine(ucfg)) {
                String t = (String) e.call("issue_token", m("{\"user\":\"alice\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}")).get("token");
                Files.write(work.resolve("utf").resolve("state.json"), notUtf8);
                Map<String, Object> r = e.call("authorize", obj("token", t, "action", "read", "resource", customer));
                check("state_io".equals(code(r)) && !r.containsKey("effect"), "a running engine refuses on a non-UTF-8 state.json: " + Json.write(r));
            }
            check("state_io".equals(startError(ucfg)), "an engine does not start on a non-UTF-8 state.json: " + startError(ucfg));
            Files.writeString(work.resolve("utf").resolve("state.json"), "[]");
            check("state_io".equals(startError(ucfg)), "nor on a state.json that is not an object");
            Files.delete(work.resolve("utf").resolve("state.json"));
            check(startError(ucfg) == null, "and starts again without it");
            Path alog = work.resolve("utf").resolve("audit.jsonl");
            byte[] goodLog = Files.readAllBytes(alog);
            try (Engine e = new Engine(ucfg)) {
                Files.write(alog, notUtf8, java.nio.file.StandardOpenOption.APPEND);
                check("audit_broken".equals(code(e.call("audit_verify", new LinkedHashMap<>()))), "audit_verify reports a non-UTF-8 log as audit_broken");
                check(Boolean.TRUE.equals(e.call("audit_tail", m("{\"n\":50}")).get("ok")), "audit_tail still answers");
                Map<String, Object> r = e.call("issue_token", m("{\"user\":\"alice\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}"));
                check(Boolean.FALSE.equals(r.get("ok")) && code(r).startsWith("audit_"), "nothing is issued onto a broken log: " + Json.write(r));
            }
            check("audit_broken".equals(startError(ucfg)), "an engine does not start on a non-UTF-8 audit log: " + startError(ucfg));
            Path ucf = work.resolve("utf.json");
            Files.writeString(ucf, Json.write(ucfg));
            String refAudit = run(with(cli, "audit", "verify", "--config", ucf.toString()));
            check(refAudit.contains("audit_broken"), "the reference agrees: " + refAudit);
            Files.write(alog, goodLog);
            check(startError(ucfg) == null, "and starts again on the intact log");
            Path ub = work.resolve("utf-bundle");
            Map<String, Object> bcfg = obj("bundle_dir", ub.toString());
            Path bcf = work.resolve("utf-bundle.json");
            Files.writeString(bcf, Json.write(bcfg));
            for (String[] f : new String[][] {{"policies.json", "bundle_io"}, {"entities.json", "bundle_io"}, {"catalog.json", "bundle_io"}, {"policies/crm.cedar", "bundle_io"}}) {
                rm(ub);
                copyBundle(root, ub);
                Files.write(ub.resolve(f[0]), notUtf8);
                check(f[1].equals(startError(bcfg)), "a non-UTF-8 " + f[0] + " is " + f[1] + ": " + startError(bcfg));
                String ref = run(with(cli, "info", "--config", bcf.toString()));
                check(ref.contains(f[1]), "the reference agrees on a non-UTF-8 " + f[0] + ": " + ref);
            }
            passed("java strictness: files that are not UTF-8");

            // -- two engines racing to create the signing key: one creates it, the others read it
            String javaBin = ProcessHandle.current().info().command().orElse("java");
            for (int round = 0; round < 3; round++) {
                Path st = work.resolve("race-" + round);
                long at = System.currentTimeMillis() + 2500;
                List<Process> procs = new ArrayList<>();
                for (int k = 0; k < 8; k++)
                    procs.add(new ProcessBuilder(javaBin, "-cp", System.getProperty("java.class.path"), "dev.smartdelegate.Conformance", "--key-race", bundleDir, st.toString(), String.valueOf(at))
                            .redirectError(ProcessBuilder.Redirect.DISCARD).start());
                java.util.Set<String> keys = new java.util.HashSet<>();
                List<String> tokens = new ArrayList<>();
                for (Process pr : procs) {
                    String out = new String(pr.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
                    check(pr.waitFor(60, java.util.concurrent.TimeUnit.SECONDS) && pr.exitValue() == 0 && out.split(" ").length == 2, "a racing engine starts and issues: " + out);
                    keys.add(out.split(" ")[0]);
                    tokens.add(out.split(" ")[1]);
                }
                check(keys.size() == 1 && keys.contains(Files.readString(st.resolve("signing_key.pub.b64")).strip()), "all racing engines use the one key on disk: " + keys);
                try (Stream<Path> s = Files.list(st)) {
                    List<String> left = s.map(x -> x.getFileName().toString()).filter(x -> x.endsWith(".tmp")).collect(Collectors.toList());
                    check(left.isEmpty(), "no temporary key files are left: " + left);
                }
                Map<String, Object> rcfg2 = new LinkedHashMap<>();
                rcfg2.put("bundle_dir", bundleDir);
                rcfg2.put("state_dir", st.toString());
                try (Engine e = new Engine(rcfg2)) {
                    for (String t : tokens)
                        check("allow".equals(e.call("authorize", obj("token", t, "action", "read", "resource", customer)).get("effect")), "every racing engine's token verifies");
                    Map<String, Object> v = e.call("audit_verify", new LinkedHashMap<>());
                    check(Boolean.TRUE.equals(v.get("ok")) && Long.valueOf(16).equals(v.get("records")), "the shared audit chain is intact: " + Json.write(v));
                }
            }
            // and engines in one JVM, on threads
            Path ts = work.resolve("race-threads");
            Map<String, Object> thcfg = new LinkedHashMap<>();
            thcfg.put("bundle_dir", bundleDir);
            thcfg.put("state_dir", ts.toString());
            java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(8);
            try {
                java.util.concurrent.CyclicBarrier gun = new java.util.concurrent.CyclicBarrier(8);
                List<java.util.concurrent.Future<String>> fs = new ArrayList<>();
                for (int k = 0; k < 8; k++)
                    fs.add(pool.submit(() -> {
                        gun.await();
                        try (Engine e = new Engine(thcfg)) {
                            Map<String, Object> t = e.call("issue_token", m("{\"user\":\"alice\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}"));
                            return e.call("info", new LinkedHashMap<>()).get("public_key") + " " + t.get("ok");
                        }
                    }));
                java.util.Set<String> seen = new java.util.HashSet<>();
                for (java.util.concurrent.Future<String> f : fs) seen.add(f.get(60, java.util.concurrent.TimeUnit.SECONDS));
                check(seen.equals(java.util.Set.of(Files.readString(ts.resolve("signing_key.pub.b64")).strip() + " true")), "engines racing on threads share one key and all issue: " + seen);
            } finally {
                pool.shutdownNow();
            }
            try (Engine e = new Engine(thcfg)) {
                Map<String, Object> v = e.call("audit_verify", new LinkedHashMap<>());
                check(Boolean.TRUE.equals(v.get("ok")) && Long.valueOf(8).equals(v.get("records")), "their audit chain is intact: " + Json.write(v));
            }
            passed("java strictness: racing to create the signing key");

            // -- an empty key file is a key still being written, never "no key"
            Path ks = work.resolve("empty-key");
            Files.createDirectories(ks);
            Path kf = ks.resolve("signing_key.pk8.b64");
            Map<String, Object> kcfg = new LinkedHashMap<>();
            kcfg.put("bundle_dir", bundleDir);
            kcfg.put("state_dir", ks.toString());
            long savedWait = Engine.keyWaitMillis;
            try {
                for (String empty : List.of("", "\n", "  \n")) {
                    Files.writeString(kf, empty);
                    Engine.keyWaitMillis = 300;
                    long t0 = System.nanoTime();
                    String err = startError(kcfg);
                    long waited = (System.nanoTime() - t0) / 1_000_000;
                    check("state_io".equals(err), "an engine does not start on an empty key file: " + err);
                    check(waited >= 300 && waited < 5000, "it waited for the content first: " + waited + " ms");
                    check(Files.readString(kf).equals(empty) && !Files.exists(ks.resolve("signing_key.pub.b64")), "and did not replace the key file");
                }
                // filled 400 ms later: the engine starts with that key and can issue
                String[] late = Crypto.keygen();
                Files.writeString(kf, "");
                Engine.keyWaitMillis = 10_000;
                Thread writer = new Thread(() -> {
                    try {
                        Thread.sleep(400);
                        Files.writeString(kf, late[0]);
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                });
                writer.start();
                long t0 = System.nanoTime();
                try (Engine e = new Engine(kcfg)) {
                    long waited = (System.nanoTime() - t0) / 1_000_000;
                    Map<String, Object> info = e.call("info", new LinkedHashMap<>());
                    check(waited >= 300 && waited < 9000, "the engine waited for the key: " + waited + " ms");
                    check(late[1].equals(info.get("public_key")) && info.get("key_id") != null && Boolean.TRUE.equals(info.get("can_issue")), "it starts with the key that arrived: " + Json.write(info));
                    Map<String, Object> t = e.call("issue_token", m("{\"user\":\"alice\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}"));
                    check(Boolean.TRUE.equals(t.get("ok")) && "allow".equals(e.call("authorize", obj("token", t.get("token"), "action", "read", "resource", customer)).get("effect")), "and can issue: " + Json.write(t));
                }
                writer.join();
                // a key file that is not a key is refused too, not ignored
                Files.writeString(kf, "bm90IGEga2V5");
                String err = startError(kcfg);
                check(err != null, "an engine does not start on a key file that is not a key");
                Files.write(kf, new byte[] {(byte) 0xff, (byte) 0xfe});
                check("state_io".equals(startError(kcfg)), "nor on a key file that is not UTF-8");
            } finally {
                Engine.keyWaitMillis = savedWait;
            }
            passed("java strictness: an empty signing key file is not \"no key\"");
        } finally {
            rm(work);
        }
    }

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    /**
     *   java -cp build dev.smartdelegate.Conformance <repo root> <reference CLI...>
     * e.g.  ... /repo python3 -m sf_smartdelegate      (with PYTHONPATH=/repo/src)
     */
    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        if (args.length == 4 && args[0].equals("--key-race")) {
            keyRaceChild(args);
            return;
        }
        Path root = Path.of(args[0]).toAbsolutePath().normalize();
        List<String> cli = List.of(args).subList(1, args.length);
        Map<String, Object> full = Json.parseObject("{\"actions\":[\"read\",\"create\",\"update\"],\"resources\":[\"crm.customer/*\",\"billing.refund/*\"],\"budget\":{\"EUR\":20000}}");

        evalVectors(root);

        // the shared vectors against the Java engine, in-process
        int total = 0, bad = 0;
        for (Map<String, Object> c : cases(root)) {
            Path state = Files.createTempDirectory("smartdelegate-java-");
            Map<String, Object> ecfg = config(root, state);
            if (c.get("_config") != null) ecfg.putAll((Map<String, Object>) c.get("_config"));
            try (Engine engine = new Engine(ecfg)) {
                List<String> failures = runCase(engine::call, c);
                total++;
                if (!failures.isEmpty()) { bad++; System.out.println("FAIL " + c.get("_suite") + ": " + c.get("name") + "\n  " + String.join("\n  ", failures)); }
            } finally {
                rm(state);
            }
        }
        report("java engine conformance (in-process)", total, bad);

        // formats shared with the reference implementation
        Path work = Files.createTempDirectory("smartdelegate-java-x-");
        try {
            Path cfg = work.resolve("smartdelegate.json"), cap = work.resolve("cap.json");
            Files.writeString(cfg, Json.write(config(root, work.resolve("state"))));
            Files.writeString(cap, Json.write(full));
            String token = run(with(cli, "token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "@" + cap, "--raw", "--config", cfg.toString()));
            String refPub = Files.readString(work.resolve("state").resolve("signing_key.pub.b64")).strip();
            String refPriv = Files.readString(work.resolve("state").resolve("signing_key.pk8.b64"));
            check(java.util.Base64.getEncoder().encodeToString(Crypto.publicFromSeed(Crypto.seedOf(refPriv))).equals(refPub), "public key derived from the reference's private key");
            Map<String, Object> vcfg = config(root, work.resolve("java-state"));
            vcfg.put("verify_only", true);
            vcfg.put("trusted_keys", List.of(refPub));
            try (Engine verifier = new Engine(vcfg)) {
                Map<String, Object> d = verifier.call("authorize", Json.parseObject("{\"token\":\"" + token + "\",\"action\":\"read\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"c-1\"}}"));
                check("allow".equals(d.get("effect")) && "alice".equals(((Map<String, Object>) d.get("principal")).get("user")), "token issued by the reference is accepted: " + Json.write(d));
                Map<String, Object> refInfo = Json.parseObject(run(with(cli, "info", "--config", cfg.toString())));
                check(d.get("policy_version").equals(refInfo.get("policy_version")), "same policy version as the reference");
                check("0.3.0".equals(verifier.call("info", new LinkedHashMap<>()).get("version")), "java reports version 0.3.0");
                check(refInfo.get("roles").equals(verifier.call("info", new LinkedHashMap<>()).get("roles")), "same roles as the reference");

                // a role token with live group membership issued by the reference: dave is in
                // no group in entities.json, so both the role and the allow depend on `grp`
                String roleToken = run(with(cli, "token", "issue", "--user", "dave", "--agent", "support-bot", "--role", "support-agent", "--groups", "support", "--raw", "--config", cfg.toString()));
                Map<String, Object> insp = verifier.call("inspect_token", Json.parseObject("{\"token\":\"" + roleToken + "\"}"));
                check(Boolean.TRUE.equals(insp.get("valid")), "role token issued by the reference is valid in java: " + Json.write(insp));
                Map<String, Object> rc = (Map<String, Object>) insp.get("claims");
                check("support-agent".equals(rc.get("role")) && Json.parse("[{\"type\":\"Group\",\"id\":\"support\"}]").equals(rc.get("grp")), "role and grp claims of the reference's token: " + Json.write(rc));
                Map<String, Object> rd = verifier.call("authorize", Json.parseObject("{\"token\":\"" + roleToken + "\",\"action\":\"read\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"c-1\"}}"));
                check("allow".equals(rd.get("effect")) && "support-agent".equals(((Map<String, Object>) rd.get("principal")).get("role")) && List.of("support-read-customer").equals(rd.get("policies")),
                        "java honours role and grp of a token issued by the reference: " + Json.write(rd));
                rd = verifier.call("authorize", Json.parseObject("{\"token\":\"" + roleToken + "\",\"action\":\"delete\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"c-1\"}}"));
                check("capability_action".equals(rd.get("reason")) && "DELEGATE-CAPABILITY-ACTION".equals(rd.get("rule")), "the role's ceiling binds in java: " + Json.write(rd));
            }
            // the audit log written by the reference verifies in Java; a tampered one does not
            Path refAudit = work.resolve("state").resolve("audit.jsonl");
            Map<String, Object> av = Audit.verify(refAudit);
            check(Boolean.TRUE.equals(av.get("ok")) && Long.valueOf(2).equals(av.get("records")), "audit chain written by the reference verifies in java: " + Json.write(av));
            Path tampered = work.resolve("tampered.jsonl");
            Files.writeString(tampered, Files.readString(refAudit).replaceFirst("\"user\":\"dave\"", "\"user\":\"alice\""));
            check(!Files.readString(tampered).equals(Files.readString(refAudit)), "the tampered copy differs");
            try {
                Audit.verify(tampered);
                check(false, "a tampered audit log must not verify");
            } catch (EngineException e) {
                check(e.code().equals("audit_broken"), "tampered audit log is detected: " + e.code());
            }
            // a token issued by Java is accepted by the reference
            try (Engine issuer = new Engine(config(root, work.resolve("java-issuer")))) {
                Map<String, Object> req = new LinkedHashMap<>();
                req.put("user", "alice");
                req.put("agent", "support-bot");
                req.put("cap", full);
                Map<String, Object> t = issuer.call("issue_token", req);
                check(Boolean.TRUE.equals(t.get("ok")), "java issues a token: " + Json.write(t));
                Map<String, Object> refCfg = config(root, work.resolve("ref-verifier"));
                refCfg.put("verify_only", true);
                refCfg.put("trusted_keys", List.of(issuer.call("info", new LinkedHashMap<>()).get("public_key")));
                Path rc = work.resolve("ref.json");
                Files.writeString(rc, Json.write(refCfg));
                Map<String, Object> d = Json.parseObject(run(with(cli, "authorize", "--token", (String) t.get("token"), "--action", "read", "--resource", "crm.customer/c-1", "--config", rc.toString())));
                check("allow".equals(d.get("effect")), "token issued by java is accepted by the reference: " + Json.write(d));
                // a role token with live group membership issued by Java
                Map<String, Object> rreq = Json.parseObject("{\"user\":\"dave\",\"agent\":\"support-bot\",\"role\":\"support-agent\",\"groups\":[\"support\"]}");
                Map<String, Object> rt = issuer.call("issue_token", rreq);
                check(Boolean.TRUE.equals(rt.get("ok")) && "support-agent".equals(rt.get("role")), "java issues a role token: " + Json.write(rt));
                Map<String, Object> rinsp = Json.parseObject(run(with(cli, "token", "inspect", "--token", (String) rt.get("token"), "--config", rc.toString())));
                Map<String, Object> rclaims = rinsp.get("claims") instanceof Map ? (Map<String, Object>) rinsp.get("claims") : Map.of();
                check(Boolean.TRUE.equals(rinsp.get("valid")) && "support-agent".equals(rclaims.get("role")) && Json.parse("[{\"type\":\"Group\",\"id\":\"support\"}]").equals(rclaims.get("grp")),
                        "role token issued by java is valid in the reference, with role and grp: " + Json.write(rinsp));
                Map<String, Object> rd = Json.parseObject(run(with(cli, "authorize", "--token", (String) rt.get("token"), "--action", "read", "--resource", "crm.customer/c-1", "--config", rc.toString())));
                check("allow".equals(rd.get("effect")) && "support-agent".equals(((Map<String, Object>) rd.get("principal")).get("role")) && List.of("support-read-customer").equals(rd.get("policies")),
                        "the reference honours role and grp of a token issued by java: " + Json.write(rd));
                // without the live membership the same user holds no role, in either engine
                rreq.remove("groups");
                check("role_not_held".equals(((Map<String, Object>) issuer.call("issue_token", rreq).get("error")).get("code")), "dave holds no role without live membership");
                // the audit log written by Java verifies in the reference
                issuer.call("authorize", Json.parseObject("{\"token\":\"" + t.get("token") + "\",\"action\":\"read\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"c-1\"},\"context\":{\"note\":\"é ✓\"}}"));
                Map<String, Object> jcfg = config(root, work.resolve("java-issuer"));
                Path jc = work.resolve("java.json");
                Files.writeString(jc, Json.write(jcfg));
                Map<String, Object> v = Json.parseObject(run(with(cli, "audit", "verify", "--config", jc.toString())));
                check(Boolean.TRUE.equals(v.get("ok")) && Long.valueOf(3).equals(v.get("records")), "audit chain written by java (with a role token) verifies in the reference: " + Json.write(v));
                Files.writeString(work.resolve("java-issuer").resolve("audit.jsonl"), Files.readString(work.resolve("java-issuer").resolve("audit.jsonl")).replaceFirst("\"role\":\"support-agent\"", "\"role\":\"supervisor\""));
                // the reference refuses to open a broken log: it prints the error code, not a JSON result
                String broken = run(with(cli, "audit", "verify", "--config", jc.toString()));
                check(broken.contains("audit_broken") && !broken.contains("\"ok\": true"), "the reference detects a tampered java audit log: " + broken);
            }
            // a bundle signed by Java verifies in the reference, and the reverse
            Path b = work.resolve("bundle");
            copyBundle(root, b);
            String[] pair = Crypto.keygen();
            Bundle.sign(b, pair[0]);
            Path sc = work.resolve("signed.json");
            Files.writeString(sc, Json.write(Map.of("bundle_dir", b.toString(), "bundle_public_key", pair[1])));
            check(Json.parseObject(run(with(cli, "info", "--config", sc.toString()))).get("bundle_signed_by") != null, "bundle signed by java verifies in the reference");
            Files.writeString(work.resolve("k.key"), "");
            run(with(cli, "bundle", "keygen", work.resolve("k").toString()));
            run(with(cli, "bundle", "sign", "--key", work.resolve("k.key").toString(), "--bundle", b.toString()));
            Map<String, Object> jb = new LinkedHashMap<>();
            jb.put("bundle_dir", b.toString());
            jb.put("bundle_public_key", Files.readString(work.resolve("k.pub")).strip());
            try (Engine e = new Engine(jb)) {
                check(e.call("info", new LinkedHashMap<>()).get("bundle_signed_by") != null, "bundle signed by the reference verifies in java");
            }
            Files.writeString(b.resolve("entities.json"), Files.readString(b.resolve("entities.json")).replaceFirst("\"region\": \"EU\"", "\"region\": \"US\""));
            try {
                new Engine(jb).close();
                check(false, "a changed bundle must not load");
            } catch (EngineException e) {
                check(e.code().equals("bundle_signature"), "changed bundle is refused: " + e.code());
            }
            // revoking a user: state.json written by one engine is honoured by the other
            Map<String, Object> ocfgJ = config(root, work.resolve("off-java"));
            Path ocJ = work.resolve("off-java.json");
            Files.writeString(ocJ, Json.write(ocfgJ));
            try (Engine e = new Engine(ocfgJ)) {
                String t = (String) e.call("issue_token", Json.parseObject("{\"user\":\"alice\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}")).get("token");
                Map<String, Object> r = e.call("revoke", Json.parseObject("{\"user\":\"alice\",\"by\":\"hr\"}"));
                check("alice".equals(r.get("revoked_user")) && r.get("issued_up_to") instanceof Long, "java revokes a user: " + Json.write(r));
                Map<String, Object> d = Json.parseObject(run(with(cli, "authorize", "--token", t, "--action", "read", "--resource", "crm.customer/c-1", "--config", ocJ.toString())));
                check("token_revoked".equals(d.get("reason")) && "alice".equals(((Map<String, Object>) d.get("principal")).get("user")), "the reference honours a user revoked by java: " + Json.write(d));
                Map<String, Object> v = Json.parseObject(run(with(cli, "audit", "verify", "--config", ocJ.toString())));
                check(Boolean.TRUE.equals(v.get("ok")) && Long.valueOf(3).equals(v.get("records")), "java's user_revoked record verifies in the reference: " + Json.write(v));
            }
            Map<String, Object> ocfgP = config(root, work.resolve("off-ref"));
            Path ocP = work.resolve("off-ref.json"), rin = work.resolve("revoke.json");
            Files.writeString(ocP, Json.write(ocfgP));
            Files.writeString(rin, "{\"user\":\"alice\",\"by\":\"hr\"}");
            String pt = run(with(cli, "token", "issue", "--user", "alice", "--agent", "support-bot", "--role", "support-agent", "--raw", "--config", ocP.toString()));
            Map<String, Object> pr = Json.parseObject(run(with(cli, "call", "revoke", "--input", "@" + rin, "--config", ocP.toString())));
            check("alice".equals(pr.get("revoked_user")), "the reference revokes a user: " + Json.write(pr));
            try (Engine e = new Engine(ocfgP)) {
                Map<String, Object> d = e.call("authorize", Json.parseObject("{\"token\":\"" + pt + "\",\"action\":\"read\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"c-1\"}}"));
                check("token_revoked".equals(d.get("reason")) && "alice".equals(((Map<String, Object>) d.get("principal")).get("user")), "java honours a user revoked by the reference: " + Json.write(d));
                Map<String, Object> v = e.call("audit_verify", new LinkedHashMap<>());
                check(Boolean.TRUE.equals(v.get("ok")) && Long.valueOf(3).equals(v.get("records")), "the reference's user_revoked record verifies in java: " + Json.write(v));
            }
            passed("java interoperability with the reference");

            // OIDC-backed issuance, with the shared ID-token fixtures (RS256)
            Map<String, Object> ids = Json.parseObject(Files.readString(root.resolve("spec/conformance/oidc/id_tokens.json")));
            Map<String, Object> ocfg = config(root, work.resolve("java-oidc"));
            Map<String, Object> idp = new LinkedHashMap<>();
            idp.put("issuer", "https://idp.example.test");
            idp.put("audience", "smartdelegate-demo");
            idp.put("jwks_file", root.resolve("spec/conformance/oidc/jwks.json").toString());
            ocfg.put("idp", idp);
            try (Engine e = new Engine(ocfg)) {
                Map<String, Object> req = new LinkedHashMap<>();
                req.put("agent", "support-bot");
                req.put("cap", full);
                req.put("id_token", ids.get("alice"));
                Map<String, Object> ok = e.call("issue_token", req);
                check("alice".equals(ok.get("user")), "ID token names the user: " + Json.write(ok));
                for (String kind : List.of("expired", "wrong_audience", "wrong_issuer", "forged")) {
                    req.put("id_token", ids.get(kind));
                    Map<String, Object> r = e.call("issue_token", req);
                    check(Boolean.FALSE.equals(r.get("ok")) && "id_token_invalid".equals(((Map<String, Object>) r.get("error")).get("code")), kind + " ID token is rejected: " + Json.write(r));
                }
                req.put("id_token", ids.get("dave"));
                check("delegation_denied".equals(((Map<String, Object>) e.call("issue_token", req).get("error")).get("code")), "policy still applies to a verified user");
            }
            passed("java OIDC issuance");
        } finally {
            rm(work);
        }

        rolesFile(root, cli);
        ancestorBudget(root, cli);
        approvalIds(root, cli);
        strictness(root, cli);

        // the shared vectors through the Java REST client and the reference daemon
        total = 0;
        bad = 0;
        for (Map<String, Object> c : cases(root)) {
            try (Daemon d = new Daemon(root, cli, (Map<String, Object>) c.get("_config"))) {
                Client client = new Client(d.url, PEP, ADMIN);
                List<String> failures = runCase(client::call, c);
                total++;
                if (!failures.isEmpty()) { bad++; System.out.println("FAIL " + c.get("_suite") + ": " + c.get("name") + "\n  " + String.join("\n  ", failures)); }
            }
        }
        report("java client conformance (REST, reference daemon)", total, bad);

        // typed helpers
        try (Daemon d = new Daemon(root, cli, null)) {
            Client iam = new Client(d.url, PEP, ADMIN);
            Map<String, Object> cap = Json.parseObject("{\"actions\":[\"read\",\"create\"],\"resources\":[\"crm.customer/*\",\"billing.refund/*\"],\"budget\":{\"EUR\":20000}}");
            String token = (String) iam.issueToken("alice", "support-bot", cap).get("token");
            Map<String, Object> record = Json.parseObject("{\"id\":\"c-1\",\"email\":\"ada@example.com\",\"ssn\":\"123-45-6789\",\"region\":\"EU\"}");
            Map<String, Object> decision = iam.require(token, "read", "crm.customer", "c-1", null);
            Object safe = iam.applyObligations(decision, record);
            check(safe.equals(Json.parseObject("{\"id\":\"c-1\",\"email\":\"ada@example.com\",\"region\":\"EU\"}")), "applyObligations masks ssn: " + Json.write(safe));
            try {
                iam.require(token, "delete", "crm.customer", "c-1", null);
                check(false, "delete should be denied");
            } catch (DeniedException e) {
                check(e.reason().equals("capability_action"), "reason " + e.reason());
            }
            Map<String, Object> spend = Json.parseObject("{\"spend\":{\"currency\":\"EUR\",\"amount\":15000}}");
            try {
                iam.require(token, "create", "billing.refund", "r-1", spend);
                check(false, "large refund should be held");
            } catch (DeniedException e) {
                check(e.approvalId() != null, "approval id present");
                iam.approve(e.approvalId(), "bob");
            }
            check("allow".equals(iam.authorize(token, "create", "billing.refund", "r-1", spend).get("effect")), "approved refund is allowed");
            Map<String, Object> narrow = Json.parseObject("{\"actions\":[\"read\"],\"resources\":[\"crm.customer/c-1\"],\"deny_labels\":[\"pii\"]}");
            String child = (String) iam.exchangeToken(token, "refund-helper", narrow, 300).get("token");
            Map<String, Object> filtered = iam.filter(child, "read", "crm.customer", "c-1", record, false, null);
            check(filtered.get("data").equals(Json.parseObject("{\"id\":\"c-1\",\"region\":\"EU\"}")), "sub-agent sees no pii: " + Json.write(filtered.get("data")));
            try {
                new Client("http://127.0.0.1:9", PEP, null).authorize(token, "read", "crm.customer", "c-1", null);
                check(false, "unreachable daemon must throw");
            } catch (SmartDelegateException e) {
                check(e.code().equals("daemon_unreachable"), e.code());
            }
            // roles through the typed helpers
            Map<String, Object> rt = iam.issueToken("dave", "support-bot", "support-agent", null, "ticket-1", List.of("support"));
            check("support-agent".equals(Client.roleOf(rt)), "issueToken with a role reports it: " + Json.write(rt));
            Map<String, Object> rd = iam.require((String) rt.get("token"), "read", "crm.customer", "c-1", null);
            check("support-agent".equals(Client.roleOf(rd)) && "DELEGATE-POLICY-PERMIT".equals(rd.get("rule")), "the decision names the role and the rule: " + Json.write(rd));
            try {
                iam.issueToken("dave", "support-bot", "support-agent", null, null, null);
                check(false, "dave holds no role without live membership");
            } catch (SmartDelegateException e) {
                check(e.code().equals("role_not_held"), e.code());
            }
            check(Client.roleOf(iam.issueToken("alice", "support-bot", cap)) == null, "a token without a role has none");
            check("ticket-1".equals(rt.get("task")), "the token result names the task: " + Json.write(rt));
            // offboarding: one call ends every token already issued for the user, sub-agent tokens included
            Map<String, Object> ru = iam.revokeUser("alice", "admin");
            check("alice".equals(ru.get("revoked_user")) && ru.get("issued_up_to") instanceof Long, "revokeUser result: " + Json.write(ru));
            check("token_revoked".equals(iam.authorize(token, "read", "crm.customer", "c-1", null).get("reason")), "alice's token is revoked");
            check("token_revoked".equals(iam.authorize(child, "read", "crm.customer", "c-1", null).get("reason")), "and so is her sub-agent's");
            check("allow".equals(iam.authorize((String) rt.get("token"), "read", "crm.customer", "c-1", null).get("effect")), "dave's token is untouched");
            try {
                iam.revokeUser("", null);
                check(false, "an empty user must be refused");
            } catch (SmartDelegateException e) {
                check(e.code().equals("invalid_input"), e.code());
            }
            passed("java client checks");
        }

        // the Java daemon and command line
        DaemonChecks.all(root, cli);
        System.exit(failed == 0 ? 0 : 1);
    }
}
