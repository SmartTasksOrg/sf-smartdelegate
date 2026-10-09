package dev.smartdelegate;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

/**
 * The command line of the Java port: the same commands, options, configuration
 * and exit codes as the reference ({@code src/sf_smartdelegate/cli.py}) and the
 * other ports, minus the proxies, the bridges, {@code init}, {@code bench}
 * and the demo.
 *
 * <pre>
 *   java -jar build/smartdelegate.jar &lt;command&gt; [options]     (or bin/smartdelegate-java)
 * </pre>
 *
 * Exit code 0: allow / ok. 2: deny. 1: error.
 */
public final class Cli {
    static final String HELP = """
            smartdelegate-java - identity and access management for LLM agents (Java port)

            USAGE
              smartdelegate-java <command> [options]     JSON options accept @file, e.g. --cap @cap.json

            SETUP
              info                                  version, policy version, mode, key id
              policy check                          load the bundle and report problems
              policy test                           run the bundle's tests/*.json
              bundle keygen <prefix>                write <prefix>.key and <prefix>.pub (Ed25519)
              bundle sign --key <file>              sign the bundle (writes bundle.sig.json)

            TOKENS
              token issue --user U --agent A (--cap JSON | --role R [--cap JSON]) [--groups g1,g2]
                          [--ttl S] [--tenant T] [--task X] [--id-token JWT] [--raw]
                                                    --role: lend the agent a role the user holds; the
                                                    token can never carry more than the role allows
              token exchange --token T --actor A [--cap JSON] [--ttl S] [--raw]
              token inspect --token T
              token revoke --id TOKEN_ID | --token T | --user U     --user ends every token already
                                                    issued for that human (offboarding)

            DECISIONS
              authorize --token T --action A --resource path/id [--attrs JSON] [--context JSON]
                        [--data JSON] [--strict] [--dry-run]      exit code 0 allow, 2 deny, 1 error
              explain   (same options)              show every check and every field decision
              approvals                             list held requests
              approve <approval_id> --by USER

            AUDIT
              audit verify                          recompute the hash chain
              audit tail [-n N]

            SERVERS
              serve [--listen 127.0.0.1:8181]       REST decision daemon

            OTHER
              call <op> [--input JSON|@file|-]      any operation of spec/API.md, JSON in, JSON out
              conformance [<vectors dir> <bundle dir>] [--root DIR]
                                                    policy evaluation cases and conformance vectors.
                                                    Without directories: the repository's spec/, found
                                                    from --root or from the working directory upwards
              --version

            NOT IN THIS PORT
              init, bench, --demo, http-proxy, mcp-proxy, bridge: use the Python package.
              bundle compile: use the Rust port.

            CONFIG
              --config FILE (or SMARTDELEGATE_CONFIG, or ./smartdelegate.json); --bundle DIR and --state DIR override it.
              --shadow logs would-be denials without enforcing them.
            """;

    private static final Set<String> SWITCHES = Set.of("raw", "strict", "dry-run", "shadow", "help");
    private static final Set<String> ELSEWHERE = Set.of("init", "bench", "demo", "http-proxy", "mcp-proxy", "bridge");

    /** Leaves {@link #run} with an exit code; the message, if any, has been printed. */
    private static final class Exit extends RuntimeException {
        private static final long serialVersionUID = 1L;
        final int code;

        Exit(int code) {
            super(null, null, false, false);
            this.code = code;
        }
    }

    private final PrintStream out, err;
    private final InputStream in;
    private final Map<String, String> env;
    private final List<String> pos = new ArrayList<>();
    private final Map<String, String> flags = new LinkedHashMap<>();

    private Cli(InputStream in, PrintStream out, PrintStream err, Map<String, String> env) {
        this.in = in;
        this.out = out;
        this.err = err;
        this.env = env;
    }

    private Exit die(String message) {
        err.println("smartdelegate: " + message);
        return new Exit(1);
    }

    // ---- arguments -------------------------------------------------------------

    private void parse(String[] argv) {
        for (int i = 0; i < argv.length; i++) {
            String x = argv[i];
            if (x.equals("--")) break;
            String name = x.startsWith("--") ? x.substring(2) : x.startsWith("-") && x.length() == 2 ? x.substring(1) : null;
            if (name == null) {
                pos.add(x);
            } else if (SWITCHES.contains(name)) {
                flags.put(name, "true");
            } else if (name.contains("=")) {
                flags.put(name.substring(0, name.indexOf('=')), name.substring(name.indexOf('=') + 1));
            } else {
                if (++i >= argv.length) throw die("--" + name + " needs a value");
                flags.put(name, argv[i]);
            }
        }
        if (has("help")) {
            pos.clear();
            pos.add("help");
        }
    }

    /** The value of an option, or null when it is absent or empty. */
    private String flag(String k) {
        String v = flags.get(k);
        return v == null || v.isEmpty() ? null : v;
    }

    private boolean has(String k) {
        return flags.containsKey(k);
    }

    private String req(String k) {
        if (!has(k)) throw die("--" + k + " is required");
        return flags.get(k);
    }

    private static String stripBom(String text) {
        return text.startsWith("﻿") ? text.substring(1) : text;
    }

    private Path path(String s) {
        try {
            return Path.of(s);
        } catch (InvalidPathException e) {
            throw die(s + ": not a valid path");
        }
    }

    private String readFile(String file) {
        try {
            return stripBom(Files.readString(path(file), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw die(file + ": " + (e instanceof CharacterCodingException ? "not UTF-8" : e.getClass().getSimpleName() + (e.getMessage() != null ? ": " + e.getMessage() : "")));
        }
    }

    private Object parseJson(String text, String what) {
        try {
            return Json.parse(text);
        } catch (RuntimeException | StackOverflowError e) {
            throw die("not valid JSON (" + (e instanceof StackOverflowError ? "nested too deeply" : e.getMessage()) + "): " + what);
        }
    }

    /** A JSON value given inline or as @file (friendlier in PowerShell and cmd). */
    private Object jsonArg(String s) {
        return parseJson(s.startsWith("@") ? readFile(s.substring(1)) : s, s);
    }

    // ---- configuration ---------------------------------------------------------

    /** Config file + command-line overrides. Relative paths in the file are relative to the file. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> loadConfig() {
        String file = flag("config");
        if (file == null && env.get("SMARTDELEGATE_CONFIG") != null && !env.get("SMARTDELEGATE_CONFIG").isEmpty()) file = env.get("SMARTDELEGATE_CONFIG");
        if (file == null && Files.exists(Path.of("smartdelegate.json"))) file = "smartdelegate.json";
        Map<String, Object> cfg = new LinkedHashMap<>();
        if (file != null) {
            String text = readFile(file);
            Object doc;
            try {
                doc = Json.parse(text);
            } catch (RuntimeException | StackOverflowError e) {
                throw die(file + ": not valid JSON (" + e.getMessage() + ")");
            }
            if (!(doc instanceof Map)) throw die(file + ": the configuration must be a JSON object");
            cfg = (Map<String, Object>) doc;
            Path base;
            try {
                base = path(file).toRealPath().getParent();
            } catch (IOException e) {
                throw die(file + ": " + e.getMessage());
            }
            fix(cfg, "bundle_dir", base);
            fix(cfg, "state_dir", base);
            if (cfg.get("idp") instanceof Map) fix((Map<String, Object>) cfg.get("idp"), "jwks_file", base);
        }
        if (flag("bundle") != null) cfg.put("bundle_dir", flag("bundle"));
        if (flag("state") != null) cfg.put("state_dir", flag("state"));
        if (has("shadow")) cfg.put("mode", "shadow");
        for (String[] k : new String[][] {{"admin_key", "SMARTDELEGATE_ADMIN_KEY"}, {"pep_key", "SMARTDELEGATE_PEP_KEY"}})
            if (env.get(k[1]) != null && !env.get(k[1]).isEmpty()) cfg.put(k[0], env.get(k[1]));
        if (!(cfg.get("bundle_dir") instanceof String b) || b.isEmpty()) throw die("no bundle: pass --config FILE or --bundle DIR");
        return cfg;
    }

    private void fix(Map<String, Object> m, String key, Path base) {
        if (m.get(key) instanceof String p && !path(p).isAbsolute()) m.put(key, base.resolve(p).toString());
    }

    private Engine engine(Map<String, Object> cfg) {
        try {
            return new Engine(cfg);
        } catch (SmartDelegateException e) {
            throw die(e.getMessage());
        } catch (InvalidPathException e) {
            throw die("invalid_config: not a valid path: " + e.getInput());
        }
    }

    private Map<String, Object> call(String op, Map<String, Object> input) {
        try (Engine e = engine(loadConfig())) {
            return e.call(op, input);
        }
    }

    // ---- output ----------------------------------------------------------------

    private int finish(Map<String, Object> v) {
        out.println(Json.pretty(v));
        return !Boolean.TRUE.equals(v.get("ok")) ? 1 : "deny".equals(v.get("effect")) ? 2 : 0;
    }

    private int tokenOut(Map<String, Object> v) {
        if (has("raw") && Boolean.TRUE.equals(v.get("ok"))) {
            out.println(v.get("token"));
            return 0;
        }
        return finish(v);
    }

    private int report(Vectors.Report r, String label) {
        for (Map<String, Object> c : r.results)
            if (!Boolean.TRUE.equals(c.get("passed"))) out.println("FAIL " + Json.format(c.get("name"), 0, true) + "\n" + Json.pretty(c.get("failures")));
        out.println(label + ": " + r.total() + " cases, " + r.failed() + " failed");
        return r.failed() == 0 ? 0 : 1;
    }

    // ---- commands --------------------------------------------------------------

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    private Map<String, Object> decisionInput() {
        String res = req("resource");
        int slash = res.indexOf('/');
        String rid = slash >= 0 ? res.substring(slash + 1) : "";
        Map<String, Object> resource = obj("path", slash >= 0 ? res.substring(0, slash) : res, "id", rid.isEmpty() ? "any" : rid);
        Map<String, Object> i = obj("action", req("action"), "resource", resource);
        if (flag("token") != null) i.put("token", flag("token"));
        if (flag("attrs") != null) resource.put("attrs", jsonArg(flag("attrs")));
        if (flag("context") != null) i.put("context", jsonArg(flag("context")));
        if (has("strict")) i.put("strict", true);
        if (has("dry-run")) i.put("dry_run", true);
        if (flag("data") != null) i.put("data", jsonArg(flag("data")));
        return i;
    }

    private void ttl(Map<String, Object> i) {
        if (flag("ttl") == null) return;
        try {
            i.put("ttl", Long.parseLong(flag("ttl").strip()));
        } catch (NumberFormatException e) {
            throw die("--ttl must be a number of seconds");
        }
    }

    /** The repository root (the directory holding spec/conformance/vectors), from {@code dir} upwards; or null. */
    private static Path findRoot(Path dir) {
        for (Path d = dir.toAbsolutePath().normalize(); d != null; d = d.getParent())
            if (Files.isDirectory(d.resolve("spec").resolve("conformance").resolve("vectors"))) return d;
        return null;
    }

    private int conformance() {
        Path root = flag("root") != null ? path(flag("root")) : findRoot(Path.of(""));
        Path vectors, bundle;
        if (pos.size() >= 3) {
            vectors = path(pos.get(1));
            bundle = path(pos.get(2));
        } else if (pos.size() == 2) {
            vectors = path(pos.get(1));
            bundle = Path.of("spec", "conformance", "bundle");
        } else {
            if (root == null) throw die("conformance: spec/conformance not found from the working directory upwards; pass --root DIR, or <vectors dir> <bundle dir>");
            vectors = root.resolve("spec").resolve("conformance").resolve("vectors");
            bundle = root.resolve("spec").resolve("conformance").resolve("bundle");
        }
        if (!Files.isDirectory(vectors)) throw die(vectors + ": not a directory");
        int code = 0;
        try {
            if (root != null && Files.exists(root.resolve("spec/conformance/eval/cases.json")))
                code |= report(Vectors.runEvalCases(root.resolve("spec/conformance/eval/cases.json")), "java policy evaluation (against real Cedar's answers)");
            else
                err.println("smartdelegate: spec/conformance/eval/cases.json not found (pass --root DIR); running the vectors only");
            Vectors.Report r = Vectors.runVectors(vectors, bundle);
            // no cases is not a pass: a wrong directory must not look like success
            if (r.total() == 0) throw die(vectors + ": no conformance cases found");
            code |= report(r, "java conformance");
        } catch (SmartDelegateException e) {
            throw die(e.getMessage());
        }
        return code;
    }

    private int serve() {
        Map<String, Object> cfg = loadConfig();
        String listen = flag("listen") != null ? flag("listen") : cfg.get("listen") instanceof String s && !s.isEmpty() ? s : "127.0.0.1:8181";
        Engine engine = engine(cfg);
        Server server;
        try {
            server = Server.listen(engine, listen, cfg.get("admin_key") instanceof String a ? a : "", cfg.get("pep_key") instanceof String p ? p : "");
        } catch (SmartDelegateException e) {
            engine.close();
            throw die(e.detail());
        }
        CountDownLatch stopped = new CountDownLatch(1);
        try {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                // SIGTERM / Ctrl-C: stop answering, then let go of the state directory.
                // A call in progress holds the engine's lock until it has finished.
                server.close();
                stopped.countDown();
            }, "smartdelegate-stop"));
        } catch (IllegalStateException ignored) {
            // already shutting down
        }
        // the first line on stderr: tests and the harness read the URL from it
        err.println("smartdelegate daemon listening on " + server.url());
        err.flush();
        try {
            stopped.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            server.close();
        }
        return 0;
    }

    @SuppressWarnings("unchecked")
    private int dispatch() {
        String cmd = pos.isEmpty() ? "help" : pos.get(0), sub = pos.size() > 1 ? pos.get(1) : "";
        String both = cmd + " " + sub;
        if (cmd.equals("help")) {
            out.print(HELP);
            return 0;
        }
        if (cmd.equals("version")) {
            out.println("smartdelegate " + Engine.VERSION + " (java)");
            return 0;
        }
        if (cmd.equals("info")) return finish(call("info", obj()));
        if (both.equals("policy check")) {
            Map<String, Object> info = call("info", obj());
            if (!Boolean.TRUE.equals(info.get("ok"))) return finish(info);
            out.println("bundle loads: " + info.get("policies") + " policies, version " + info.get("policy_version"));
            return 0;
        }
        if (both.equals("policy test")) {
            Vectors.Report r;
            try {
                r = Vectors.runBundleTests(path((String) loadConfig().get("bundle_dir")));
            } catch (SmartDelegateException e) {
                throw die(e.getMessage());
            }
            for (Map<String, Object> c : r.results) {
                out.println((Boolean.TRUE.equals(c.get("passed")) ? "ok  " : "FAIL") + " " + c.get("name"));
                if (!Boolean.TRUE.equals(c.get("passed"))) out.println(Json.pretty(c.get("failures")));
            }
            out.println(r.total() + " tests, " + r.failed() + " failed");
            return r.failed() == 0 ? 0 : 1;
        }
        if (both.equals("bundle keygen")) {
            if (pos.size() <= 2) throw die("usage: smartdelegate-java bundle keygen <prefix>");
            String prefix = pos.get(2);
            String[] pair = Engine.keygen();
            Path key = path(prefix + ".key"), pub = path(prefix + ".pub");
            try {
                Files.deleteIfExists(key);   // so the mode below applies to a file that already existed
                try {
                    Files.createFile(key, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                } catch (UnsupportedOperationException e) {
                    // not a POSIX file system (Windows): the file inherits the directory's ACL
                    Files.createFile(key);
                }
                Files.writeString(key, pair[0], StandardCharsets.UTF_8);
                Files.writeString(pub, pair[1], StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw die(e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            out.println("wrote " + prefix + ".key (keep secret) and " + prefix + ".pub\nset \"bundle_public_key\": \"" + pair[1] + "\" in smartdelegate.json to require signed bundles");
            return 0;
        }
        if (both.equals("bundle sign")) {
            Path dir = path((String) loadConfig().get("bundle_dir"));
            String key = readFile(req("key"));
            try {
                Map<String, Object> v = Engine.signBundle(dir, key);
                out.println("signed bundle version " + v.get("version") + " with key " + v.get("key_id"));
            } catch (SmartDelegateException e) {
                throw die(e.getMessage());
            }
            return 0;
        }
        if (both.equals("bundle compile"))
            throw die("compiling .cedar to policies.json needs the Cedar toolchain: run `smartdelegate bundle compile` from the Rust port (ports/rust)");
        if (both.equals("token issue")) {
            Map<String, Object> i = obj("agent", req("agent"));
            if (flag("cap") != null) i.put("cap", jsonArg(flag("cap")));
            else if (flag("role") == null) throw die("--cap JSON or --role NAME is required");
            for (String[] k : new String[][] {{"user", "user"}, {"tenant", "tenant"}, {"task", "task"}, {"id_token", "id-token"}, {"role", "role"}})
                if (flag(k[1]) != null) i.put(k[0], flag(k[1]));
            if (has("groups")) {
                List<Object> groups = new ArrayList<>();
                for (String g : flags.get("groups").split(",")) if (!g.isEmpty()) groups.add(g);
                i.put("groups", groups);
            }
            ttl(i);
            return tokenOut(call("issue_token", i));
        }
        if (both.equals("token exchange")) {
            Map<String, Object> i = obj("subject_token", req("token"), "actor", req("actor"));
            if (flag("cap") != null) i.put("cap", jsonArg(flag("cap")));
            ttl(i);
            return tokenOut(call("exchange_token", i));
        }
        if (both.equals("token inspect")) return finish(call("inspect_token", obj("token", req("token"))));
        if (both.equals("token revoke")) {
            Map<String, Object> i = flag("user") != null ? obj("user", flag("user")) : flag("id") != null ? obj("token_id", flag("id")) : obj("token", req("token"));
            i.put("by", "cli");
            return finish(call("revoke", i));
        }
        if (cmd.equals("call") && !sub.isEmpty()) {
            // any operation, input as JSON: the form other ports and scripts use
            String raw = flag("input") != null ? flag("input") : "{}";
            Object input;
            if (raw.equals("-")) {
                String text;
                try {
                    text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                            .decode(ByteBuffer.wrap(in.readAllBytes())).toString();
                } catch (IOException e) {
                    throw die("standard input: " + (e instanceof CharacterCodingException ? "not UTF-8" : e.getMessage()));
                }
                input = parseJson(stripBom(text), "standard input");
            } else {
                input = jsonArg(raw);
            }
            // anything but an object is the engine's to refuse (invalid_input)
            return finish(call(sub, input instanceof Map ? (Map<String, Object>) input : null));
        }
        if (cmd.equals("authorize")) {
            Map<String, Object> i = decisionInput();
            return finish(call(i.containsKey("data") ? "filter" : "authorize", i));
        }
        if (cmd.equals("explain")) return finish(call("explain", decisionInput()));
        if (cmd.equals("approvals")) return finish(call("approvals", obj()));
        if (cmd.equals("approve") && !sub.isEmpty()) return finish(call("approve", obj("approval_id", sub, "by", req("by"))));
        if (both.equals("audit verify")) return finish(call("audit_verify", obj()));
        if (both.equals("audit tail")) {
            long n = 20;
            if (flag("n") != null) {
                try {
                    n = Math.max(0, Math.min(Integer.MAX_VALUE, Long.parseLong(flag("n").strip())));
                } catch (NumberFormatException e) {
                    throw die("-n must be a number");
                }
            }
            Map<String, Object> r = call("audit_tail", obj("n", n));
            if (!Boolean.TRUE.equals(r.get("ok")) && r.get("error") instanceof Map<?, ?> m) {
                // exit code 0 and no records, as the reference and the other ports; the reason goes to stderr
                err.println("smartdelegate: " + m.get("code") + ": " + m.get("message"));
            }
            if (r.get("records") instanceof List<?> records) for (Object rec : records) out.println(Json.write(rec));
            return 0;
        }
        if (cmd.equals("serve")) return serve();
        if (cmd.equals("conformance")) return conformance();
        if (ELSEWHERE.contains(cmd)) throw die("'" + cmd + "' is not part of the Java port: use the Python package (`python -m sf_smartdelegate " + cmd + "`)");
        err.print(HELP);
        return 1;
    }

    /** Run one command. Never calls {@code System.exit}; returns the exit code. */
    public static int run(String[] argv, InputStream in, PrintStream out, PrintStream err, Map<String, String> env) {
        Cli cli = new Cli(in, out, err, env);
        int code;
        try {
            if (argv.length > 0 && (argv[0].equals("--version") || argv[0].equals("-V"))) {
                out.println("smartdelegate " + Engine.VERSION + " (java)");
                code = 0;
            } else if (argv.length > 0 && (argv[0].equals("--help") || argv[0].equals("-h"))) {
                out.print(HELP);
                code = 0;
            } else if (argv.length > 0 && argv[0].equals("--demo")) {
                throw cli.die("'--demo' is not part of the Java port: use the Python package (`python -m sf_smartdelegate --demo`)");
            } else {
                cli.parse(argv);
                code = cli.dispatch();
            }
        } catch (Exit e) {
            code = e.code;
        } catch (RuntimeException | StackOverflowError e) {
            // a bug is an error, never an allow
            err.println("smartdelegate: internal: " + e);
            code = 1;
        }
        out.flush();
        err.flush();
        return code;
    }

    public static void main(String[] args) {
        PrintStream out = new PrintStream(new java.io.BufferedOutputStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), 1 << 16), false, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.err), true, StandardCharsets.UTF_8);
        int code = run(args, System.in, out, err, System.getenv());
        // a failed write (closed pipe, full disk) must not look like success
        if (out.checkError() && code == 0) code = 1;
        System.exit(code);
    }
}
