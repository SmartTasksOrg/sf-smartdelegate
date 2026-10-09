package dev.smartdelegate;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

/**
 * The SmartDelegate engine, in-process: issues and exchanges capability tokens,
 * answers authorization requests, applies field obligations and writes the
 * audit log.
 *
 * <p>This is a port of the Python reference (src/sf_smartdelegate/engine.py) and
 * passes the same conformance vectors. Every operation is JSON in, JSON out:
 *
 * <pre>
 * Engine iam = new Engine(Map.of("bundle_dir", "bundle", "state_dir", "state"));
 * Map&lt;String,Object&gt; d = iam.call("authorize", request);   // never throws on bad input
 * </pre>
 *
 * Decision order (first failure wins, default deny): token, catalog, tenant,
 * capability, policy, obligations (row filter, rate limit), budget, human
 * approval, fields, strict mode.
 *
 * <p>Thread-safe. Java processes sharing a state directory are serialised by
 * a lock file. The lock is NOT shared with the Python and Rust ports (they
 * use a different kind of file lock), so do not point this port and another
 * port at the same state directory.
 */
public final class Engine implements AutoCloseable {
    public static final String VERSION = "0.3.0";
    private static final Pattern COLUMN = Pattern.compile("^[A-Za-z0-9_]+$");
    private static final Pattern INT = Pattern.compile("^-?\\d+$");
    private static final Pattern RATE = Pattern.compile("^\\s*(\\d+)\\s*/\\s*(\\d+)\\s*$");

    /** A deny reached inside a decision: not an error, a result. */
    private static final class Deny extends RuntimeException {
        private static final long serialVersionUID = 1L;
        final String code, detail;
        transient Map<String, Object> claims;

        Deny(String code, String detail) {
            super(code, null, false, false);
            this.code = code;
            this.detail = detail;
        }
    }

    private static final class Principal {
        String user, tenant, task, jti;
        List<String> chain, anc;
        Tokens.Cap cap;
        long exp;
        /** budgets of ancestor tokens carried by the token: {token id: {currency: amount}} */
        Map<String, Object> lim = Map.of();
        /** the role the human is acting in for this task, or null */
        String role;
        /** live group membership [{type, id}] that replaces entities.json for this user, or null to use entities.json */
        List<Map<String, Object>> groups;

        String leaf() {
            return chain.isEmpty() ? "" : chain.get(chain.size() - 1);
        }

        Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("user", user);
            m.put("agent", leaf());
            m.put("chain", chain);
            m.put("tenant", tenant);
            m.put("task", task);
            m.put("role", role);
            m.put("token_id", jti);
            return m;
        }

        @SuppressWarnings("unchecked")
        static Principal of(Map<String, Object> claims) {
            Principal p = new Principal();
            p.user = Tokens.userOf(claims);
            p.chain = Tokens.chainOf(claims);
            p.tenant = claims.get("tnt") instanceof String s ? s : null;
            p.task = claims.get("task") instanceof String s ? s : null;
            p.jti = (String) claims.get("jti");
            p.anc = new ArrayList<>((List<String>) claims.get("anc"));
            p.cap = Tokens.Cap.fromJson(claims.get("cap"));
            p.exp = (Long) claims.get("exp");
            p.role = claims.get("role") instanceof String s ? s : null;
            if (claims.get("lim") instanceof Map) p.lim = (Map<String, Object>) claims.get("lim");
            p.groups = claims.get("grp") instanceof List ? (List<Map<String, Object>>) claims.get("grp") : null;
            return p;
        }
    }

    private static final class Outcome {
        boolean allow;
        String reason = "", detail = "";
        List<String> policies = new ArrayList<>();
        Principal principal;
        Map<String, String> mask;
        List<String> fieldAllow = new ArrayList<>(), fieldDeny = new ArrayList<>(), fieldRedact = new ArrayList<>();
        List<Object> rowFilter = new ArrayList<>();
        List<Object[]> rate = new ArrayList<>();
        Map<String, Object> rateLimit, approval;
        String[] approved;
        Object[] spend;
        List<Object> errors = new ArrayList<>(), trace = new ArrayList<>();
    }

    // config
    private final Path bundleDir, stateDir;
    private final String issuer, bundlePublicKey;
    private final boolean shadow, trustCallerChain, allowTestClock, requireRole;
    private final long maxTtl, defaultTtl, approvalTtl;
    private final int maxDepth;
    private Map<String, Object> idp;

    private Bundle bundle;
    private final Tokens.Keys keys;
    private Map<String, Object> state = emptyState();
    private String stateRaw = "";
    private final Audit audit;
    private final Map<String, ArrayDeque<Long>> rate = new HashMap<>();
    private long counter = 0;
    /**
     * One lock per state directory for the whole JVM: the file lock below
     * serialises processes, but a JVM may not take the same file lock twice,
     * so engines in one JVM that share a directory share this lock first.
     */
    private static final Map<Path, ReentrantLock> DIR_LOCKS = new java.util.concurrent.ConcurrentHashMap<>();
    private final ReentrantLock mutex;
    private FileChannel lockChannel;

    // ---- small helpers -------------------------------------------------------

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    private static String s(Object map, String key) {
        return map instanceof Map<?, ?> m && m.get(key) instanceof String x && !x.isEmpty() ? x : null;
    }

    private static String req(Object map, String key) {
        String x = s(map, key);
        if (x == null) throw new EngineException("invalid_input", "'" + key + "' is required");
        return x;
    }

    private static long num(Map<String, Object> m, String key, long dflt) {
        return m.get(key) instanceof Long l ? l : dflt;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) {
        return (Map<String, Object>) o;
    }

    private static Cedar.Entity entity(String type, String id) {
        if (!Cedar.validType(type)) throw new EngineException("invalid_input", "'" + type + "' is not a valid entity type");
        return new Cedar.Entity(type, id);
    }

    private static final List<String> STATE_KEYS = List.of("revoked", "approvals", "pending", "ledger", "limits", "revoked_users");

    private static Map<String, Object> emptyState() {
        Map<String, Object> m = new LinkedHashMap<>();
        for (String k : STATE_KEYS) m.put(k, new LinkedHashMap<String, Object>());
        return m;
    }

    private Map<String, Object> st(String key) {
        return map(state.get(key));
    }

    // ---- bundle signing --------------------------------------------------------

    /** A new Ed25519 key pair in the formats every port shares: {private key (base64 PKCS#8), public key (base64 of the 32 raw bytes)}. */
    public static String[] keygen() {
        return Crypto.keygen();
    }

    /**
     * Sign the bundle in {@code bundleDir} with a private key from {@link #keygen()}:
     * writes {@code bundle.sig.json} and returns its content ({@code files},
     * {@code version}, {@code key_id}, {@code alg}, {@code signature}). An
     * engine configured with the matching {@code bundle_public_key} then
     * refuses the bundle when a file changes. Throws {@link EngineException}.
     */
    public static Map<String, Object> signBundle(Path bundleDir, String privateKeyB64) {
        if (bundleDir == null || privateKeyB64 == null) throw new EngineException("invalid_input", "a bundle directory and a private key are required");
        return Bundle.sign(bundleDir, privateKeyB64);
    }

    // ---- construction ----------------------------------------------------------

    public Engine(Map<String, Object> c) {
        if (c == null) throw new EngineException("invalid_input", "config must be an object");
        bundleDir = Path.of(req(c, "bundle_dir"));
        stateDir = s(c, "state_dir") != null ? Path.of(s(c, "state_dir")) : null;
        issuer = s(c, "issuer") != null ? s(c, "issuer") : "smartdelegate://local";
        String mode = s(c, "mode") != null ? s(c, "mode") : "enforce";
        if (!mode.equals("enforce") && !mode.equals("shadow")) throw new EngineException("invalid_config", "mode must be 'enforce' or 'shadow'");
        shadow = mode.equals("shadow");
        trustCallerChain = Boolean.TRUE.equals(c.get("trust_caller_chain"));
        allowTestClock = Boolean.TRUE.equals(c.get("allow_test_clock"));
        bundlePublicKey = s(c, "bundle_public_key");
        maxTtl = num(c, "max_ttl", 3600);
        defaultTtl = num(c, "default_ttl", 900);
        maxDepth = (int) num(c, "max_depth", 4);
        approvalTtl = num(c, "approval_ttl", 900);
        requireRole = Boolean.TRUE.equals(c.get("require_role"));
        if (c.get("idp") instanceof Map) {
            Map<String, Object> i = map(c.get("idp"));
            Object jwks = i.get("jwks");
            if (!(jwks instanceof Map)) {
                try {
                    jwks = Json.parseObject(Files.readString(Path.of(req(i, "jwks_file")), StandardCharsets.UTF_8));
                } catch (EngineException e) {
                    throw e;
                } catch (IOException | RuntimeException e) {
                    throw new EngineException("invalid_config", "jwks_file: " + e.getMessage());
                }
            }
            Object gmap = i.get("group_map");
            if (gmap != null && !(gmap instanceof Map<?, ?> gm && gm.values().stream().allMatch(x -> x instanceof String)))
                throw new EngineException("invalid_config", "idp.group_map must map a claim value to a group id");
            String gtype = s(i, "group_type") != null ? s(i, "group_type") : "Group";
            if (!Cedar.validType(gtype)) throw new EngineException("invalid_config", "idp.group_type is not a valid entity type");
            idp = obj("issuer", req(i, "issuer"), "audience", req(i, "audience"), "jwks", jwks, "user_claim", s(i, "user_claim") != null ? s(i, "user_claim") : "sub",
                    "groups_claim", s(i, "groups_claim"), "group_type", gtype, "group_map", gmap,
                    // set only when the keys came from a file: reload reads it again
                    "jwks_file", i.get("jwks") instanceof Map ? null : s(i, "jwks_file"));
        }
        bundle = new Bundle(bundleDir, bundlePublicKey);
        mutex = stateDir != null ? DIR_LOCKS.computeIfAbsent(stateDir.toAbsolutePath().normalize(), k -> new ReentrantLock()) : new ReentrantLock();
        String priv = null;
        try {
            if (stateDir != null) Files.createDirectories(stateDir);
            if (Boolean.TRUE.equals(c.get("verify_only"))) {
                priv = null;
            } else if (s(c, "signing_key") != null) {
                priv = s(c, "signing_key");
            } else if (stateDir != null) {
                Path kp = stateDir.resolve("signing_key.pk8.b64");
                priv = Files.exists(kp) ? readKey(kp) : createKey(kp);
            } else {
                priv = Crypto.keygen()[0];
            }
            List<String> trusted = new ArrayList<>();
            if (c.get("trusted_keys") instanceof List<?> l) for (Object k : l) if (k instanceof String str) trusted.add(str);
            keys = new Tokens.Keys(priv, trusted);
            if (stateDir != null) lockChannel = FileChannel.open(stateDir.resolve("lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        } catch (IOException e) {
            throw new EngineException("state_io", String.valueOf(e.getMessage()));
        }
        try {
            mutex.lock();
            FileLock fl = null;
            try {
                fl = lockFile();
                refreshState();
                audit = stateDir != null && !Boolean.FALSE.equals(c.get("audit")) ? new Audit(stateDir.resolve("audit.jsonl")) : null;
            } finally {
                release(fl);
                mutex.unlock();
            }
        } catch (RuntimeException e) {
            close();
            throw e;
        }
    }

    /** How long to wait for an empty signing key file to get its content. Package-private so tests can shorten it. */
    static volatile long keyWaitMillis = 30_000;

    /**
     * The signing key file. An empty file means another process is still
     * writing it: wait for the content, then fail with state_io. An empty key
     * is never read as "no key", which would silently turn an issuer into a
     * verify-only engine.
     */
    private static String readKey(Path kp) throws IOException {
        long deadline = System.nanoTime() + keyWaitMillis * 1_000_000L;
        while (true) {
            String text = Files.readString(kp, StandardCharsets.UTF_8).strip();
            if (!text.isEmpty()) return text;
            if (System.nanoTime() - deadline > 0) throw new EngineException("state_io", kp + " is empty");
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new EngineException("state_io", kp + " is empty");
            }
        }
    }

    private static void ownerOnly(Path p) throws IOException {
        try {
            Files.setPosixFilePermissions(p, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // not a POSIX filesystem
        }
    }

    /**
     * Create the signing key, safely when several processes start on an empty
     * state directory at once: exactly one creates it, the others read it.
     * The key is written to a private temporary file and then given its name
     * with a hard link, which fails if the name exists and never exposes a
     * half-written file. Where hard links are unavailable, an exclusive
     * create is used instead.
     */
    private String createKey(Path kp) throws IOException {
        String[] pair = Crypto.keygen();
        Path tmp = stateDir.resolve("signing_key." + Crypto.randomHex(8) + ".tmp");
        boolean created;
        try {
            Files.writeString(tmp, "", StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
            ownerOnly(tmp);
            Files.writeString(tmp, pair[0], StandardCharsets.UTF_8);
            try {
                Files.createLink(kp, tmp);
                created = true;
            } catch (java.nio.file.FileAlreadyExistsException e) {
                created = false;
            } catch (UnsupportedOperationException | IOException e) {
                try {
                    Files.writeString(kp, "", StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
                    ownerOnly(kp);
                    Files.writeString(kp, pair[0], StandardCharsets.UTF_8);
                    created = true;
                } catch (java.nio.file.FileAlreadyExistsException e2) {
                    created = false;
                }
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
        if (!created) return readKey(kp);      // another process created the key between the check and now
        Files.writeString(stateDir.resolve("signing_key.pub.b64"), pair[1], StandardCharsets.UTF_8);
        return pair[0];
    }

    private FileLock lockFile() {
        if (lockChannel == null) return null;
        try {
            return lockChannel.lock();
        } catch (IOException e) {
            throw new EngineException("state_io", "cannot lock the state directory: " + e.getMessage());
        }
    }

    private static void release(FileLock fl) {
        if (fl != null) {
            try {
                fl.release();
            } catch (IOException ignored) {
                // nothing useful to do
            }
        }
    }

    @Override
    public void close() {
        if (lockChannel != null) {
            try {
                lockChannel.close();
            } catch (IOException ignored) {
                // closing
            }
            lockChannel = null;
        }
    }

    // ---- state -----------------------------------------------------------------

    private void refreshState() {
        if (stateDir == null) return;
        Path p = stateDir.resolve("state.json");
        if (!Files.exists(p)) return;
        String text;
        try {
            text = Files.readString(p, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new EngineException("state_io", String.valueOf(e.getMessage()));
        }
        if (text.equals(stateRaw)) return;
        try {
            Map<String, Object> data = Json.parseObject(text);
            for (String k : STATE_KEYS) {
                data.putIfAbsent(k, new LinkedHashMap<String, Object>());
                if (!(data.get(k) instanceof Map)) throw new IllegalArgumentException();
            }
            state = data;
            stateRaw = text;
        } catch (RuntimeException e) {
            // an unreadable state file must not silently drop revocations
            throw new EngineException("state_io", "state.json is corrupt");
        }
    }

    private void saveState() {
        if (stateDir == null) return;
        String text = Json.write(state);
        try {
            Path tmp = stateDir.resolve("state.json.tmp");
            Files.writeString(tmp, text, StandardCharsets.UTF_8);
            Files.move(tmp, stateDir.resolve("state.json"), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new EngineException("state_io", String.valueOf(e.getMessage()));
        }
        stateRaw = text;
    }

    private void pruneState(long now) {
        st("revoked").values().removeIf(v -> (Long) v + 86400 <= now);
        st("approvals").values().removeIf(v -> (Long) map(v).get("exp") <= now);
        st("pending").values().removeIf(v -> (Long) map(v).get("requested_at") + 86400 <= now);
    }

    // ---- entry point -----------------------------------------------------------

    /** JSON in, JSON out. Never throws on bad input; errors come back as {"ok": false, "error": {code, message}}. */
    public Map<String, Object> call(String op, Map<String, Object> payload) {
        mutex.lock();
        FileLock fl = null;
        try {
            fl = lockFile();
            if (payload == null) throw new EngineException("invalid_input", "the request body must be a JSON object");
            refreshState();
            Map<String, Object> out = dispatch(op, payload);
            out.put("ok", true);
            return out;
        } catch (EngineException e) {
            return e.toJson();
        } catch (StackOverflowError e) {
            return new EngineException("invalid_input", "the request is nested too deeply").toJson();
        } catch (RuntimeException e) {
            // a bug must surface as a refusal, never as an allow or a crash
            return new EngineException("internal", e.getClass().getSimpleName() + ": " + e.getMessage()).toJson();
        } finally {
            release(fl);
            mutex.unlock();
        }
    }

    private Map<String, Object> dispatch(String op, Map<String, Object> i) {
        switch (op == null ? "" : op) {
            case "authorize": return decide(i, false);
            case "filter": return decide(i, true);
            case "explain": {
                Map<String, Object> j = new LinkedHashMap<>(i);
                j.put("explain", true);
                j.put("dry_run", true);
                return decide(j, i.containsKey("data"));
            }
            case "issue_token": return issueToken(i);
            case "exchange_token": return exchangeToken(i);
            case "inspect_token": return inspectToken(i);
            case "apply_obligations": return applyObligations(i);
            case "revoke": return revoke(i);
            case "approve": return approve(i);
            case "approvals": return obj("pending", st("pending"), "granted", st("approvals"));
            case "audit_verify":
                if (audit == null) throw new EngineException("no_audit", "this engine has no audit log (no state_dir, or audit is off)");
                if (!Files.exists(audit.path)) return obj("records", 0L, "head", Audit.GENESIS);
                return Audit.verify(audit.path);
            case "audit_tail":
                if (audit == null) throw new EngineException("no_audit", "this engine has no audit log");
                return obj("records", Audit.tail(audit.path, (int) num(i, "n", 20)));
            case "info": return info();
            case "reload":
                // a bundle that fails to load leaves the old one in force
                Bundle fresh = new Bundle(bundleDir, bundlePublicKey);
                // the provider's signing keys are re-read too, so a key rotation
                // needs a reload, not a restart; a file that fails to load leaves
                // the old keys (and the old bundle) in force
                if (idp != null && idp.get("jwks_file") instanceof String file) {
                    Map<String, Object> jwks;
                    try {
                        jwks = Json.parseObject(Files.readString(Path.of(file), StandardCharsets.UTF_8));
                        if (!(jwks.get("keys") instanceof List)) throw new IllegalArgumentException("no 'keys' list");
                    } catch (IOException | RuntimeException | StackOverflowError e) {
                        throw new EngineException("invalid_config", "jwks_file: " + e.getMessage());
                    }
                    idp.put("jwks", jwks);
                }
                bundle = fresh;
                audit(obj("event", "bundle_reloaded", "policy_version", bundle.version), System.currentTimeMillis() / 1000);
                return info();
            default: throw new EngineException("unknown_op", "no operation named '" + op + "'");
        }
    }

    private Map<String, Object> info() {
        return obj("version", VERSION, "implementation", "java", "policy_version", bundle.version, "bundle_signed_by", bundle.signedBy,
                "policies", (long) bundle.policies.size(), "resources", new ArrayList<>(bundle.catalog.keySet()), "roles", new ArrayList<>(bundle.roles.keySet()), "mode", shadow ? "shadow" : "enforce",
                "issuer", issuer, "key_id", keys.kid, "public_key", keys.publicB64, "can_issue", keys.canSign(),
                "oidc", idp != null ? idp.get("issuer") : null);
    }

    private long now(Map<String, Object> i) {
        if (allowTestClock && i.get("now") instanceof Long n) return n;
        return System.currentTimeMillis() / 1000;
    }

    /** Fail closed: when the decision cannot be recorded, the operation fails. */
    private void audit(Map<String, Object> record, long ts) {
        if (audit == null) return;
        try {
            audit.append(record, ts);
        } catch (EngineException e) {
            throw new EngineException("audit_io", "the decision could not be recorded, so it is refused: " + e.detail());
        }
    }

    // ---- tokens ------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private Map<String, Object> verifyToken(String token, long now) {
        Map<String, Object> claims;
        try {
            claims = keys.verify(token, issuer);
        } catch (IllegalArgumentException e) {
            throw new Deny("token_invalid", e.getMessage());
        }
        if (Tokens.chainOf(claims).isEmpty()) throw new Deny("token_invalid", "the token names no agent");
        Deny d = null;
        if ((Long) claims.get("exp") <= now) {
            d = new Deny("token_expired", "the capability token has expired");
        } else if ((Long) claims.get("iat") > now + 60) {
            d = new Deny("token_invalid", "the capability token is dated in the future");
        } else {
            List<String> ids = new ArrayList<>((List<String>) claims.get("anc"));
            ids.add((String) claims.get("jti"));
            for (String id : ids) {
                if (st("revoked").containsKey(id)) {
                    d = new Deny("token_revoked", "token " + id + " in the delegation chain was revoked");
                    break;
                }
            }
            // offboarding: every token of this user issued up to the cut-off is dead
            if (d == null && st("revoked_users").get(Tokens.userOf(claims)) instanceof Long cutoff && (Long) claims.get("iat") <= cutoff)
                d = new Deny("token_revoked", "every token issued for this user up to the cut-off was revoked");
        }
        if (d != null) {
            d.claims = claims;      // signature was good: the denial can be attributed
            throw d;
        }
        return claims;
    }

    private Map<String, Object> iamContext(Principal p) {
        return obj("user_attrs", bundle.attrs.getOrDefault("User::" + p.user, new LinkedHashMap<String, Object>()),
                "user", obj("__entity", obj("type", "User", "id", p.user)),
                "user_id", p.user, "chain", new ArrayList<>(p.chain), "depth", (long) p.chain.size(),
                "root_agent", obj("__entity", obj("type", "Agent", "id", p.chain.isEmpty() ? "" : p.chain.get(0))),
                "tenant", p.tenant == null ? "" : p.tenant, "task", p.task == null ? "" : p.task, "role", p.role == null ? "" : p.role);
    }

    /**
     * The entity store this principal is judged against. A token that carries
     * live group membership replaces what entities.json says about that user;
     * everything else is unchanged.
     */
    private Cedar.Store storeFor(Principal p) {
        if (p.groups == null) return bundle.store;
        List<Cedar.Entity> parents = new ArrayList<>();
        for (Map<String, Object> g : p.groups) parents.add(new Cedar.Entity((String) g.get("type"), (String) g.get("id")));
        return bundle.store.withParents(new Cedar.Entity("User", p.user), parents);
    }

    /**
     * Normalise group membership supplied at issuance: names or {type, id}.
     * Groups that entities.json does not define are dropped; the result is
     * sorted by (type, id) and free of duplicates, so every port writes the
     * same claim.
     */
    private List<Map<String, Object>> groups(Object raw, String defaultType, Map<String, Object> mapping) {
        if (raw instanceof String str) raw = List.of(str);
        if (!(raw instanceof List<?> list)) throw new EngineException("invalid_input", "groups must be a list of group names or {type, id}");
        java.util.TreeSet<String[]> out = new java.util.TreeSet<>((x, y) -> {
            int c = Json.BY_CODE_POINT.compare(x[0], y[0]);
            return c != 0 ? c : Json.BY_CODE_POINT.compare(x[1], y[1]);
        });
        for (Object g : list) {
            String t, n;
            if (g instanceof String name) {
                if (mapping != null) {
                    if (!mapping.containsKey(name)) continue;
                    name = (String) mapping.get(name);
                }
                t = defaultType;
                n = name;
            } else if (g instanceof Map<?, ?> m && m.get("type") instanceof String mt && m.get("id") instanceof String mi) {
                t = mt;
                n = mi;
            } else {
                throw new EngineException("invalid_input", "groups must be a list of group names or {type, id}");
            }
            if (Cedar.validType(t) && bundle.store.contains(new Cedar.Entity(t, n))) out.add(new String[] {t, n});
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (String[] g : out) result.add(obj("type", g[0], "id", g[1]));
        return result;
    }

    private static List<String> sortedUnion(List<String> a, List<String> b) {
        java.util.TreeSet<String> s = new java.util.TreeSet<>(Json.BY_CODE_POINT);
        s.addAll(a);
        s.addAll(b);
        return new ArrayList<>(s);
    }

    /**
     * The human lends the agent one of their roles for this task. Sets the
     * capability the token gets on {@code p.cap} and returns its lifetime;
     * throws when the human does not hold the role or asks for more than the
     * role allows.
     */
    private long applyRole(String name, Principal p, long ttl) {
        Bundle.Role role = bundle.roles.get(name);
        if (role == null) throw new EngineException("unknown_role", "roles.json defines no role named '" + name + "'");
        Cedar.Entity user = new Cedar.Entity("User", p.user);
        Cedar.Store store = storeFor(p);
        if (role.members.stream().noneMatch(m -> store.isIn(user, m)))
            throw new EngineException("role_not_held", "user '" + p.user + "' does not hold the role '" + name + "'");
        if (role.agents != null && role.agents.stream().noneMatch(a -> Tokens.Cap.matches(a, p.leaf())))
            throw new EngineException("role_exceeded", "agent '" + p.leaf() + "' may not be started in the role '" + name + "'");
        if (role.tasks != null && !(p.task != null && role.tasks.stream().anyMatch(t -> Tokens.Cap.matches(t, p.task))))
            throw new EngineException("role_exceeded", "the role '" + name + "' covers only tasks matching: " + String.join(", ", role.tasks));
        if (p.cap == null) {
            p.cap = Tokens.Cap.fromJson(role.cap.toJson());
        } else {
            // what the role never sees, the token never sees
            Tokens.Cap cap = new Tokens.Cap(p.cap.actions, p.cap.resources, sortedUnion(p.cap.denyLabels, role.cap.denyLabels),
                    sortedUnion(p.cap.denyFields, role.cap.denyFields), p.cap.budget);
            try {
                cap.checkNarrowerThan(role.cap);
            } catch (EngineException e) {
                throw new EngineException("role_exceeded", "more than the role '" + name + "' allows: " + e.detail());
            }
            p.cap = cap;
        }
        return role.maxTtl != null ? Math.min(ttl, role.maxTtl) : ttl;
    }

    private record Verdict(boolean allow, List<String> policies, List<Object> errors, boolean forbidError) {}

    private Verdict evaluate(Cedar.Entity principal, String action, Cedar.Entity resource, Map<String, Object> ctx, Cedar.Store store) {
        Cedar.Result r = Cedar.isAuthorized(bundle.policies, new Cedar.Env(principal, entity("Action", action), resource, ctx, store));
        List<Object> errors = new ArrayList<>();
        boolean forbidError = false;
        for (String[] e : r.errors()) {
            boolean isForbid = !bundle.policies.get(e[0]).permit;
            forbidError |= isForbid;
            errors.add(obj("policy", e[0], "effect", isForbid ? "forbid" : "permit", "error", e[1]));
        }
        return new Verdict(r.allow() && !forbidError, r.reasons(), errors, forbidError);
    }

    private void checkDelegation(Cedar.Entity delegator, String agent, Principal p, Tokens.Cap cap, long ttl) {
        Cedar.Entity agentUid = entity("Agent", agent);
        if (!bundle.store.contains(agentUid)) throw new EngineException("unknown_agent", "agent '" + agent + "' is not registered in entities.json");
        Map<String, Object> ctx;
        try {
            ctx = map(Cedar.fromJson(obj("iam", iamContext(p), "requested",
                    obj("actions", cap.actions, "resources", cap.resources, "ttl", ttl, "budget", new LinkedHashMap<String, Object>(cap.budget)))));
        } catch (IllegalArgumentException e) {
            throw new EngineException("invalid_input", e.getMessage());
        }
        Verdict v = evaluate(delegator, "delegate", agentUid, ctx, storeFor(p));
        if (!v.allow()) {
            String why = v.policies().isEmpty() ? "no policy permits it" : "forbidden by " + String.join(", ", v.policies());
            throw new EngineException("delegation_denied", delegator + " may not delegate to agent '" + agent + "': " + why);
        }
    }

    private static Tokens.Cap parseCap(Map<String, Object> i) {
        if (i.get("cap") == null) return null;
        Tokens.Cap cap = Tokens.Cap.fromJson(i.get("cap"));
        cap.validate();
        return cap;
    }

    private long ttl(Map<String, Object> i) {
        return Math.max(1, Math.min(num(i, "ttl", defaultTtl), maxTtl));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mint(Map<String, Object> claims, String event, long now) {
        String jti = Crypto.randomHex(12);
        claims.put("jti", jti);
        String token = keys.sign(claims);
        Map<String, Object> cap = map(claims.get("cap"));
        if (!map(cap.get("budget")).isEmpty()) {
            st("limits").put(jti, new LinkedHashMap<>(map(cap.get("budget"))));
            pruneState(now);
            saveState();
        }
        String user = Tokens.userOf(claims);
        List<String> chain = Tokens.chainOf(claims);
        long exp = (Long) claims.get("exp");
        audit(obj("event", event, "token_id", jti, "user", user, "chain", chain, "tenant", claims.get("tnt"), "task", claims.get("task"),
                "role", claims.get("role"), "ancestors", claims.get("anc"), "exp", exp, "cap", cap, "policy_version", bundle.version), now);
        return obj("token", token, "token_type", "Bearer", "issued_token_type", "urn:ietf:params:oauth:token-type:jwt", "token_id", jti,
                "expires_at", exp, "expires_in", exp - now, "user", user, "chain", chain, "role", claims.get("role"), "task", claims.get("task"), "cap", cap);
    }

    private Map<String, Object> issueToken(Map<String, Object> i) {
        long now = now(i);
        String user;
        List<Map<String, Object>> groups = null;
        String idt = s(i, "id_token");
        if (idt != null) {
            if (idp == null) throw new EngineException("no_idp", "no OIDC provider is configured");
            Map<String, Object> claims = Tokens.verifyIdToken(idt, map(idp.get("jwks")), (String) idp.get("issuer"), (String) idp.get("audience"), now);
            user = s(claims, (String) idp.get("user_claim"));
            if (user == null) throw new EngineException("id_token_invalid", "ID token has no '" + idp.get("user_claim") + "' claim");
            if (s(i, "user") != null && !s(i, "user").equals(user)) throw new EngineException("id_token_invalid", "the ID token belongs to a different user");
            // Offboarding also covers sign-ins that happened before it: an ID
            // token issued at or before the user's revoke cut-off cannot start
            // a new agent, however long the provider says it lives.
            if (st("revoked_users").get(user) instanceof Long cutoff && !(claims.get("iat") instanceof Long iat && iat > cutoff))
                throw new EngineException("id_token_invalid", "the ID token was issued before this user was revoked; sign in again");
            String gc = (String) idp.get("groups_claim");
            if (gc != null) {
                // the identity provider is the authority on what this human
                // is a member of right now; a missing claim means "of nothing".
                // A dotted name reads a nested claim (Keycloak: realm_access.roles)
                // when there is no top-level claim of that exact name.
                Object raw = claims.get(gc);
                if (raw == null && gc.contains(".")) {
                    raw = lookup(claims, gc);
                    if (raw == Deny.class) raw = null;
                }
                try {
                    groups = groups(raw == null ? List.of() : raw, (String) idp.get("group_type"), idp.get("group_map") == null ? null : map(idp.get("group_map")));
                } catch (EngineException e) {
                    throw new EngineException("id_token_invalid", "the '" + gc + "' claim is not a list of group names");
                }
            }
        } else {
            user = req(i, "user");
            if (i.get("groups") != null) groups = groups(i.get("groups"), "Group", null);
        }
        String agent = req(i, "agent");
        Tokens.Cap cap = parseCap(i);
        String role = s(i, "role");
        if (role == null && requireRole) throw new EngineException("role_required", "this engine issues tokens only for a named role");
        if (cap == null && role == null) throw new EngineException("invalid_cap", "'cap' is required: a root token must state what it may do");
        long ttl = ttl(i);
        Principal p = new Principal();
        p.user = user;
        p.chain = List.of(agent);
        p.tenant = s(i, "tenant");
        p.task = s(i, "task");
        p.anc = List.of();
        p.cap = cap;
        p.exp = now + ttl;
        p.role = role;
        p.groups = groups;
        if (role != null) {
            ttl = applyRole(role, p, ttl);
            cap = p.cap;
            p.exp = now + ttl;
        }
        checkDelegation(entity("User", user), agent, p, cap, ttl);
        Map<String, Object> claims = obj("iss", issuer, "aud", Tokens.AUDIENCE, "sub", "user:" + user, "iat", now, "exp", now + ttl, "jti", "",
                "act", Tokens.actFor(p.chain), "anc", new ArrayList<String>(), "cap", cap.toJson());
        if (p.tenant != null) claims.put("tnt", p.tenant);
        if (p.task != null) claims.put("task", p.task);
        if (role != null) claims.put("role", role);
        if (groups != null) claims.put("grp", groups);
        return mint(claims, "token_issued", now);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> exchangeToken(Map<String, Object> i) {
        long now = now(i);
        Map<String, Object> parent;
        try {
            parent = verifyToken(req(i, "subject_token"), now);
        } catch (Deny d) {
            throw new EngineException(d.code, d.detail);
        }
        Principal pp = Principal.of(parent);
        String actor = req(i, "actor");
        if (pp.chain.size() >= maxDepth) throw new EngineException("depth_exceeded", "delegation chains are limited to " + maxDepth + " agents");
        Tokens.Cap cap = parseCap(i);
        if (cap == null) cap = pp.cap;
        cap.checkNarrowerThan(pp.cap);
        long exp = Math.min(now + ttl(i), (Long) parent.get("exp"));
        if (s(i, "task") != null && pp.task != null && !s(i, "task").equals(pp.task))
            throw new EngineException("widening", "a sub-agent token cannot change the task it was issued for");
        if (s(i, "role") != null && !s(i, "role").equals(pp.role))
            throw new EngineException("widening", "a sub-agent token cannot change the role it was issued for");
        checkDelegation(entity("Agent", pp.leaf()), actor, pp, cap, exp - now);
        List<String> chain = new ArrayList<>(pp.chain);
        chain.add(actor);
        List<String> anc = new ArrayList<>((List<String>) parent.get("anc"));
        anc.add((String) parent.get("jti"));
        Map<String, Object> claims = obj("iss", issuer, "aud", Tokens.AUDIENCE, "sub", parent.get("sub"), "iat", now, "exp", exp, "jti", "",
                "act", Tokens.actFor(chain), "anc", anc, "cap", cap.toJson());
        if (parent.get("tnt") instanceof String t && !t.isEmpty()) claims.put("tnt", t);
        String task = pp.task != null ? pp.task : s(i, "task");
        if (task != null) claims.put("task", task);
        if (pp.role != null) claims.put("role", pp.role);
        if (pp.groups != null) claims.put("grp", pp.groups);
        // every ancestor's budget travels with the token (see the budget check)
        Map<String, Object> lim = new LinkedHashMap<>(pp.lim);
        if (!pp.cap.budget.isEmpty()) lim.put(pp.jti, new LinkedHashMap<String, Object>(pp.cap.budget));
        if (!lim.isEmpty()) claims.put("lim", lim);
        return mint(claims, "token_exchanged", now);
    }

    private Map<String, Object> inspectToken(Map<String, Object> i) {
        long now = now(i);
        try {
            Map<String, Object> c = verifyToken(req(i, "token"), now);
            return obj("valid", true, "claims", c, "chain", Tokens.chainOf(c), "user", Tokens.userOf(c), "expires_in", (Long) c.get("exp") - now);
        } catch (Deny d) {
            return obj("valid", false, "reason", d.code, "detail", d.detail);
        }
    }

    private Map<String, Object> revoke(Map<String, Object> i) {
        long now = now(i);
        if (i.containsKey("user")) {
            // Offboarding, or a human who lost a role: one call ends every
            // token already issued for them, sub-agents included. New tokens
            // are a matter of role membership, not of this list.
            if (!(i.get("user") instanceof String user) || user.isEmpty()) throw new EngineException("invalid_input", "'user' must be a non-empty string");
            // the cut-off only ever moves forward: a clock that steps back (or a
            // second machine with a slower clock) must not revive dead tokens
            long cutoff = st("revoked_users").get(user) instanceof Long prev ? Math.max(now, prev) : now;
            st("revoked_users").put(user, cutoff);
            saveState();
            audit(obj("event", "user_revoked", "user", user, "issued_up_to", cutoff, "by", s(i, "by")), now);
            return obj("revoked_user", user, "issued_up_to", cutoff);
        }
        String id;
        long exp;
        if (s(i, "token") != null) {
            try {
                Map<String, Object> c = keys.verify(s(i, "token"), issuer);
                id = (String) c.get("jti");
                exp = (Long) c.get("exp");
            } catch (IllegalArgumentException e) {
                throw new EngineException("token_invalid", e.getMessage());
            }
        } else {
            id = req(i, "token_id");
            exp = now + maxTtl;
        }
        st("revoked").put(id, exp);
        saveState();
        audit(obj("event", "token_revoked", "token_id", id, "by", s(i, "by")), now);
        return obj("revoked", id);
    }

    private Map<String, Object> approve(Map<String, Object> i) {
        long now = now(i);
        String aid = req(i, "approval_id"), by = req(i, "by");
        Object pend = st("pending").get(aid);
        if (pend == null) throw new EngineException("unknown_approval", "no pending request with that approval id");
        Map<String, Object> pending = map(pend);
        if (by.equals(pending.get("user"))) throw new EngineException("self_approval", "the user an agent acts for cannot approve that agent's request");
        // who may approve is itself policy: action "approve" on the agent
        Map<String, Object> ctx = map(Cedar.fromJson(obj("label", pending.get("label"), "for_user", pending.get("user"), "action", pending.get("action"))));
        Verdict v = evaluate(entity("User", by), "approve", entity("Agent", (String) pending.get("agent")), ctx, bundle.store);
        if (!v.allow()) throw new EngineException("approval_denied", "no policy lets '" + by + "' approve this request");
        st("pending").remove(aid);
        long exp = now + num(i, "ttl", approvalTtl);
        st("approvals").put(aid, obj("by", by, "exp", exp));
        saveState();
        audit(obj("event", "approval_granted", "approval_id", aid, "by", by, "label", pending.get("label"), "for_user", pending.get("user"),
                "agent", pending.get("agent"), "action", pending.get("action"), "resource", pending.get("resource")), now);
        return obj("approved", aid, "by", by, "expires_at", exp);
    }

    /** Apply the obligations of an earlier decision to data that arrived later. Pure: it authorises nothing by itself. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> applyObligations(Map<String, Object> i) {
        if (!(i.get("obligations") instanceof Map)) throw new EngineException("invalid_input", "'obligations' from a decision is required");
        if (!i.containsKey("data")) throw new EngineException("invalid_input", "'data' is required");
        Map<String, Object> ob = map(i.get("obligations"));
        if (!(ob.get("fields") instanceof Map)) throw new EngineException("invalid_input", "obligations.fields is missing; only an allow decision carries a field mask");
        Map<String, Object> f = map(ob.get("fields"));
        Map<String, String> status = new HashMap<>();
        for (String[] k : new String[][] {{"allow", Fields.ALLOW}, {"deny", Fields.DENY}, {"redact", Fields.REDACT}})
            if (f.get(k[0]) instanceof List<?> l) for (Object n : l) if (n instanceof String name) status.put(name, k[1]);
        List<Object> rf = new ArrayList<>();
        if (ob.get("row_filter") instanceof List<?> l) for (Object c : l) if (c instanceof Map) rf.add(c);
        Fields.Result r = Fields.apply(i.get("data"), status, rf);
        if (s(i, "decision_id") != null)
            audit(obj("event", "obligations_applied", "decision_id", s(i, "decision_id"), "masked", r.masked(), "rows_dropped", (long) r.rowsDropped()), now(i));
        return obj("data", r.data(), "masked", r.masked(), "rows_dropped", (long) r.rowsDropped());
    }

    // ---- decisions ---------------------------------------------------------------

    private static Object lookup(Object root, String dotted) {
        Object cur = root;
        for (String part : dotted.split("\\.", -1)) {
            if (!(cur instanceof Map<?, ?> m) || !m.containsKey(part)) return Deny.class;      // sentinel: not found
            cur = m.get(part);
        }
        return cur;
    }

    /** {@code column == context.key}, {@code column == "literal"}, {@code column == 42}, joined by {@code &&}. */
    private static List<Object> parseRowFilter(String expr, Map<String, Object> ctx) {
        List<Object> out = new ArrayList<>();
        for (String clause : expr.split("&&")) {
            String[] parts = clause.split("==", 2);
            String col = parts[0].strip();
            if (parts.length != 2 || !COLUMN.matcher(col).matches()) throw new Deny("policy_error", "row_filter clause '" + clause.strip() + "' is not `column == value`");
            String rhs = parts[1].strip();
            Object value;
            if (rhs.startsWith("context.")) {
                value = lookup(ctx, rhs.substring(8));
                if (!(value instanceof String || value instanceof Long || value instanceof Boolean))
                    throw new Deny("obligation_unresolved", "row filter needs " + rhs + ", which the request did not supply");
            } else if (rhs.length() >= 2 && rhs.startsWith("\"") && rhs.endsWith("\"")) {
                value = rhs.substring(1, rhs.length() - 1);
            } else if (INT.matcher(rhs).matches()) {
                value = Long.parseLong(rhs);
            } else {
                throw new Deny("policy_error", "row_filter value '" + rhs + "' is not context.<key>, a quoted string or an integer");
            }
            out.add(obj("column", col, "op", "eq", "value", value));
        }
        return out;
    }

    private Outcome evaluateRequest(Map<String, Object> i, long now, boolean dryRun) {
        Outcome o = new Outcome();
        try {
            steps(o, i, now, dryRun);
        } catch (Deny d) {
            o.reason = d.code;
            o.detail = d.detail;
            o.trace.add(obj("check", d.code, "result", "deny", "detail", d.detail));
        }
        return o;
    }

    @SuppressWarnings("unchecked")
    private void steps(Outcome o, Map<String, Object> i, long now, boolean dryRun) {
        String action = req(i, "action");
        if (!(i.get("resource") instanceof Map)) throw new EngineException("invalid_input", "'resource' must be an object with a 'path'");
        Map<String, Object> res = map(i.get("resource"));
        String path = req(res, "path");
        String rid = s(res, "id") != null ? s(res, "id") : "any";
        Object rawCtx = i.get("context");
        if (rawCtx != null && !(rawCtx instanceof Map)) throw new EngineException("invalid_context", "'context' must be an object");
        Map<String, Object> callerCtx = rawCtx == null ? new LinkedHashMap<>() : map(rawCtx);
        if (callerCtx.containsKey("iam")) throw new EngineException("invalid_context", "'iam' is reserved: identity comes from the token, not from the caller");

        // 1. principal
        Principal principal;
        String token = s(i, "token");
        Object chain = i.get("chain");
        if (token != null) {
            try {
                principal = Principal.of(verifyToken(token, now));
            } catch (Deny d) {
                if (d.claims != null) o.principal = Principal.of(d.claims);
                throw d;
            }
        } else if (chain instanceof Map && trustCallerChain) {
            List<String> agents = new ArrayList<>();
            if (map(chain).get("agents") instanceof List<?> l) for (Object a : l) if (a instanceof String str) agents.add(str);
            if (agents.isEmpty()) throw new EngineException("invalid_input", "chain.agents must list at least one agent");
            principal = new Principal();
            principal.user = req(chain, "user");
            principal.chain = agents;
            principal.tenant = s(chain, "tenant");
            principal.task = s(chain, "task");
            principal.anc = List.of();
            principal.cap = Tokens.Cap.unrestricted();
            principal.exp = now;
            principal.role = s(chain, "role");
            principal.groups = map(chain).get("groups") != null ? groups(map(chain).get("groups"), "Group", null) : null;
        } else if (chain != null) {
            throw new Deny("token_invalid", "this engine does not trust caller-supplied chains; send a capability token");
        } else {
            throw new Deny("token_invalid", "no capability token was presented");
        }
        o.principal = principal;
        o.trace.add(obj("check", "token", "result", "pass", "detail", "user " + principal.user + " via " + String.join(" -> ", principal.chain)));

        // 2. catalog
        Map<String, Object> rdef = bundle.catalog.get(path);
        if (rdef == null) throw new Deny("unknown_resource", "'" + path + "' is not in the catalog");
        Map<String, Object> fieldDefs = map(rdef.get("fields"));

        // 3. tenant
        Object rawAttrs = res.get("attrs");
        if (rawAttrs != null && !(rawAttrs instanceof Map)) throw new EngineException("invalid_input", "resource.attrs must be an object");
        Map<String, Object> attrs = rawAttrs == null ? new LinkedHashMap<>() : map(rawAttrs);
        if (principal.tenant != null && attrs.get("tenant") instanceof String rt && !principal.tenant.equals(rt))
            throw new Deny("tenant_mismatch", "token tenant '" + principal.tenant + "' cannot touch a resource of tenant '" + rt + "'");

        // 4. capability
        if (!principal.cap.allowsAction(action)) throw new Deny("capability_action", "the token does not carry action '" + action + "'");
        if (!principal.cap.allowsResource(path, rid)) throw new Deny("capability_resource", "the token does not cover " + path + "/" + rid);
        o.trace.add(obj("check", "capability", "result", "pass", "detail", "token covers the action and the resource"));

        // 5. policy
        String etype = (String) rdef.get("entity_type");
        Cedar.Entity rUid = entity(etype, rid);
        List<String> fieldNames = new ArrayList<>();
        if (i.get("fields") instanceof List<?> requested) {
            for (Object f : requested) {
                if (!(f instanceof String name) || !fieldDefs.containsKey(name)) throw new Deny("unknown_field", "'" + path + "." + f + "' is not in the catalog");
                fieldNames.add(name);
            }
        } else {
            fieldNames.addAll(fieldDefs.keySet());
        }
        List<Object> extra = new ArrayList<>();
        if (!bundle.store.contains(rUid)) {
            extra.add(obj("uid", obj("type", etype, "id", rid), "attrs", attrs, "parents", List.of()));
        } else if (!attrs.isEmpty()) {
            throw new EngineException("invalid_input", rUid + " is defined in entities.json; do not send attrs for it");
        }
        for (String n : fieldNames) {
            String fid = path + "." + n;
            extra.add(obj("uid", obj("type", "Field", "id", fid),
                    "attrs", obj("path", fid, "name", n, "resource", path, "labels", map(fieldDefs.get(n)).get("labels"), "of", obj("__entity", obj("type", etype, "id", rid))),
                    "parents", List.of(obj("type", etype, "id", rid))));
        }
        Cedar.Store store;
        try {
            store = storeFor(principal).overlay(extra);
        } catch (IllegalArgumentException e) {
            throw new EngineException("invalid_input", "resource entity: " + e.getMessage());
        }
        Map<String, Object> fullCtx = new LinkedHashMap<>(callerCtx);
        fullCtx.put("iam", iamContext(principal));
        Map<String, Object> ctx;
        try {
            ctx = map(Cedar.fromJson(fullCtx));
        } catch (IllegalArgumentException e) {
            throw new EngineException("invalid_context", e.getMessage() + " (use integers, strings, booleans, lists and objects; no floats or nulls)");
        }
        Cedar.Entity pUid = entity("Agent", principal.leaf());
        Verdict v = evaluate(pUid, action, rUid, ctx, store);
        o.errors.addAll(v.errors());
        o.policies = v.policies();
        if (!v.allow()) {
            if (v.forbidError()) throw new Deny("policy_error", "a forbid policy failed to evaluate, so the request is denied");
            if (v.policies().isEmpty()) throw new Deny("no_matching_permit", "no policy permits this request");
            throw new Deny("policy_forbid", "forbidden by " + String.join(", ", v.policies()));
        }
        o.trace.add(obj("check", "policy", "result", "pass", "detail", "permitted by " + String.join(", ", v.policies())));

        // 6. obligations carried by the permits that decided
        String approvalLabel = null;
        for (String pid : v.policies()) {
            Map<String, String> ann = bundle.policies.get(pid).annotations;
            if (ann.containsKey("row_filter")) {
                try {
                    o.rowFilter.addAll(parseRowFilter(ann.get("row_filter"), fullCtx));
                } catch (Deny d) {
                    throw new Deny(d.code, pid + ": " + d.detail);
                }
            }
            if (ann.containsKey("rate_limit")) {
                java.util.regex.Matcher m = RATE.matcher(ann.get("rate_limit"));
                if (!m.matches() || Long.parseLong(m.group(2)) <= 0) throw new Deny("policy_error", pid + ": rate_limit must be \"<count>/<seconds>\"");
                o.rate.add(new Object[] {pid + "|" + principal.leaf() + "|" + principal.user, Long.parseLong(m.group(1)), Long.parseLong(m.group(2))});
            }
            if (ann.containsKey("require_approval")) approvalLabel = ann.get("require_approval");
        }
        for (Object[] r : o.rate) {
            long n = (Long) r[1], w = (Long) r[2];
            ArrayDeque<Long> q = rate.computeIfAbsent((String) r[0], k -> new ArrayDeque<>());
            while (!q.isEmpty() && q.peekFirst() <= now - w) q.pollFirst();
            o.rateLimit = obj("limit", n, "window_seconds", w, "used", (long) q.size());
            if (q.size() >= n) throw new Deny("rate_limited", "more than " + n + " calls in " + w + " seconds");
        }

        // 7. budget
        if (callerCtx.containsKey("spend")) {
            Object sp = callerCtx.get("spend");
            Object cur = sp instanceof Map<?, ?> m ? m.get("currency") : null;
            Object amt = sp instanceof Map<?, ?> m ? m.get("amount") : null;
            if (!(cur instanceof String currency) || !(amt instanceof Long amount) || amount < 0)
                throw new EngineException("invalid_context", "context.spend must be {currency: string, amount: non-negative integer in minor units}");
            if (principal.jti == null) throw new Deny("budget_exceeded", "spending needs a capability token with a budget");
            Long own = principal.cap.budget.get(currency);
            if (own == null) throw new Deny("budget_exceeded", "the token carries no " + currency + " budget");
            long spentOwn = spent(principal.jti, currency);
            if (spentOwn + amount > own)
                throw new Deny("budget_exceeded", amount + " " + currency + " would exceed this token's budget of " + own + " (already spent " + spentOwn + ")");
            for (String a : principal.anc) {
                // An ancestor's budget is in this engine's state when it issued
                // the ancestor, and in the token's `lim` claim always: a
                // verify-only engine elsewhere must enforce it too.
                Object limit = st("limits").get(a) instanceof Map<?, ?> lm ? lm.get(currency) : null;
                if (limit == null) limit = principal.lim.get(a) instanceof Map<?, ?> tm ? tm.get(currency) : null;
                if (limit instanceof Long max && spent(a, currency) + amount > max)
                    throw new Deny("budget_exceeded", amount + " " + currency + " would exceed the budget of ancestor token " + a);
            }
            o.spend = new Object[] {currency, amount};
            o.trace.add(obj("check", "budget", "result", "pass", "detail", "within the budget of every token in the chain"));
        }

        // 8. human approval, last so nobody is asked to approve a doomed request
        if (approvalLabel != null) {
            String aid = Crypto.hashValue(obj("user", principal.user, "chain", principal.chain, "tenant", principal.tenant, "action", action,
                    "resource", path + "/" + rid, "attrs", attrs, "context", callerCtx, "label", approvalLabel)).substring(0, 24);
            Object grant = st("approvals").get(aid);
            if (grant instanceof Map<?, ?> g && (Long) g.get("exp") > now) {
                o.approved = new String[] {aid, (String) g.get("by")};
                o.trace.add(obj("check", "approval", "result", "pass", "detail", "approved by " + g.get("by")));
            } else {
                if (!dryRun) {
                    st("pending").put(aid, obj("label", approvalLabel, "user", principal.user, "agent", principal.leaf(), "action", action,
                            "resource", path + "/" + rid, "requested_at", now));
                    saveState();
                }
                o.approval = obj("id", aid, "label", approvalLabel);
                throw new Deny("approval_required", "a human must approve this (" + approvalLabel + ")");
            }
        }

        // 9. fields
        Map<String, String> status = new HashMap<>();
        List<Object> fieldTrace = new ArrayList<>();
        for (String n : fieldNames) {
            String fid = path + "." + n;
            Map<String, Object> fdef = map(fieldDefs.get(n));
            List<Object> labels = (List<Object>) fdef.get("labels");
            boolean allowed;
            Object by;
            if (principal.cap.denyFields.contains(fid) || labels.stream().anyMatch(principal.cap.denyLabels::contains)) {
                allowed = false;
                by = "capability";
            } else {
                Verdict fv = evaluate(pUid, action, new Cedar.Entity("Field", fid), ctx, store);
                o.errors.addAll(fv.errors());
                allowed = fv.allow();
                by = fv.policies().isEmpty() ? "no_matching_permit" : fv.policies();
            }
            if (allowed) {
                o.fieldAllow.add(n);
                status.put(n, Fields.ALLOW);
            } else {
                o.fieldDeny.add(n);
                if ("redact".equals(fdef.get("mask"))) {
                    o.fieldRedact.add(n);
                    status.put(n, Fields.REDACT);
                } else {
                    status.put(n, Fields.DENY);
                }
            }
            fieldTrace.add(obj("field", n, "effect", allowed ? "allow" : "deny", "by", by));
        }
        o.trace.add(obj("check", "fields", "result", "pass", "fields", fieldTrace));
        o.mask = status;
        o.allow = true;
        o.reason = "policy_permit";
    }

    private long spent(String tokenId, String currency) {
        return st("ledger").get(tokenId) instanceof Map<?, ?> m && m.get(currency) instanceof Long l ? l : 0;
    }

    private Map<String, Object> decide(Map<String, Object> i, boolean withData) {
        long now = now(i);
        boolean dryRun = Boolean.TRUE.equals(i.get("dry_run"));
        boolean strict = Boolean.TRUE.equals(i.get("strict"));
        if (withData && !i.containsKey("data")) throw new EngineException("invalid_input", "'data' is required for filter");
        Object data = withData ? i.get("data") : null;
        Outcome o = evaluateRequest(i, now, dryRun);

        // 10. strict mode: for tool inputs, where silently dropping a field would change what the agent asked for
        if (o.allow && strict && withData) {
            List<String> denied = Fields.apply(data, o.mask, List.of()).masked();
            if (!denied.isEmpty()) {
                o.allow = false;
                o.reason = "field_denied";
                o.detail = "the input contains fields this principal may not use: " + String.join(", ", denied);
                o.trace.add(obj("check", "field_denied", "result", "deny", "detail", o.detail));
            }
        }

        // commit the side effects of an allowed call
        if (o.allow && !dryRun) {
            for (Object[] r : o.rate) rate.computeIfAbsent((String) r[0], k -> new ArrayDeque<>()).addLast(now);
            boolean dirty = false;
            if (o.spend != null && o.principal != null) {
                List<String> ids = new ArrayList<>(o.principal.anc);
                ids.add(o.principal.jti);
                for (String id : ids) {
                    Map<String, Object> bucket = map(st("ledger").computeIfAbsent(id, k -> new LinkedHashMap<String, Object>()));
                    bucket.put((String) o.spend[0], (bucket.get(o.spend[0]) instanceof Long l ? l : 0L) + (Long) o.spend[1]);
                }
                dirty = true;
            }
            if (o.approved != null) {
                st("approvals").remove(o.approved[0]);      // an approval is good for one call
                dirty = true;
            }
            if (dirty) saveState();
        }

        boolean wouldDeny = !o.allow;
        boolean shadowed = shadow && wouldDeny;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("effect", o.allow || shadowed ? "allow" : "deny");
        out.put("reason", shadowed ? "shadow_allow" : o.reason);
        out.put("rule", EngineException.ruleId((String) out.get("reason")));
        if (!o.detail.isEmpty() && !shadowed) out.put("detail", o.detail);
        out.put("policies", o.policies);
        out.put("policy_version", bundle.version);
        out.put("principal", o.principal != null ? o.principal.toJson() : null);
        if (shadow) {
            out.put("shadow", true);
            if (wouldDeny) out.put("would_deny", obj("reason", o.reason, "detail", o.detail));
        }
        if (o.approval != null) out.put("approval", o.approval);

        Map<String, Object> obligations = new LinkedHashMap<>();
        List<String> masked = List.of();
        long rowsDropped = 0;
        if (o.allow) {
            obligations.put("fields", obj("allow", o.fieldAllow, "deny", o.fieldDeny, "redact", o.fieldRedact));
            if (!o.rowFilter.isEmpty()) obligations.put("row_filter", o.rowFilter);
            if (o.rateLimit != null) obligations.put("rate_limit", o.rateLimit);
            if (o.approved != null) obligations.put("approved", obj("id", o.approved[0], "by", o.approved[1]));
        }
        if (withData) {
            if (o.allow) {
                Fields.Result f = Fields.apply(data, o.mask, o.rowFilter);
                masked = f.masked();
                rowsDropped = f.rowsDropped();
                if (shadow) {
                    // shadow mode never changes data; it reports what it would do
                    out.put("data", data);
                    out.put("would_mask", masked);
                    out.put("would_drop_rows", rowsDropped);
                } else {
                    out.put("data", f.data());
                    out.put("masked", masked);
                    out.put("rows_dropped", rowsDropped);
                }
            } else {
                out.put("data", shadowed ? data : null);
            }
        }
        out.put("obligations", obligations);
        if (!o.errors.isEmpty()) out.put("policy_errors", o.errors);
        if (Boolean.TRUE.equals(i.get("explain"))) out.put("explain", o.trace);

        counter++;
        Principal p = o.principal;
        String requestHash;
        try {
            requestHash = Crypto.hashValue(obj("action", i.get("action"), "resource", i.get("resource"), "context", i.get("context"), "token_id", p != null ? p.jti : null));
        } catch (IllegalArgumentException e) {
            requestHash = Crypto.sha256Hex(Json.write(obj("action", i.get("action"), "resource", i.get("resource"), "context", i.get("context"))));
        }
        String decisionId = "d-" + Crypto.sha256Hex(requestHash + now + counter + ProcessHandle.current().pid()).substring(0, 16);
        out.put("decision_id", decisionId);

        if (!dryRun) {
            Object res = i.get("resource");
            audit(obj("event", "decision", "decision_id", decisionId, "op", withData ? "filter" : "authorize",
                    "effect", o.allow ? "allow" : "deny", "reason", o.reason, "detail", o.detail, "enforced", !shadow,
                    "policies", o.policies, "policy_version", bundle.version,
                    "user", p != null ? p.user : null, "chain", p != null ? p.chain : null, "role", p != null ? p.role : null, "tenant", p != null ? p.tenant : null,
                    "task", p != null ? p.task : null, "token_id", p != null ? p.jti : null, "token_exp", p != null ? (Object) p.exp : null,
                    "action", i.get("action"),
                    "resource", (s(res, "path") != null ? s(res, "path") : "?") + "/" + (s(res, "id") != null ? s(res, "id") : "any"),
                    "obligations", obligations, "masked", masked, "rows_dropped", rowsDropped, "approval", o.approval,
                    "spend", o.spend != null ? obj("currency", o.spend[0], "amount", o.spend[1]) : null,
                    "request_hash", requestHash), now);
        }
        return out;
    }
}
