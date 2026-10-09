package dev.smartdelegate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

/**
 * Policy bundle: compiled policies ({@code policies.json}, Cedar's JSON
 * policy form), entity store, field catalog, roles, signature. A port of
 * src/sf_smartdelegate/bundle.py.
 */
final class Bundle {
    final Path dir;
    final String version;
    String signedBy;
    final Map<String, Cedar.Policy> policies = new LinkedHashMap<>();
    final Cedar.Store store;
    /** "Type::id" -> attrs exactly as written in entities.json */
    final Map<String, Object> attrs = new LinkedHashMap<>();
    /** path -> {entity_type, fields: {name -> {labels, mask}}} */
    final Map<String, Map<String, Object>> catalog = new TreeMap<>();
    /** role name -> Role, sorted by code point */
    final Map<String, Role> roles = new TreeMap<>(Json.BY_CODE_POINT);

    /**
     * A role a human holds and can lend to an agent for one task: who holds
     * it ({@code members}: the user itself, or any group the user is in), the
     * ceiling ({@code cap}), and optional limits on lifetime, task and agent.
     * {@code bindings} is for bridges and is ignored by the engine.
     */
    static final class Role {
        private static final Set<String> KEYS = Set.of("description", "members", "cap", "max_ttl", "tasks", "agents", "bindings");
        final String name;
        final List<Cedar.Entity> members = new ArrayList<>();
        final Tokens.Cap cap;
        final Long maxTtl;
        final List<String> tasks, agents;
        final Map<String, Object> bindings;

        private static List<String> patternList(Object v, String what) {
            List<String> out = new ArrayList<>();
            boolean ok = v instanceof List<?> l && !l.isEmpty();
            if (ok) {
                for (Object x : (List<?>) v) {
                    if (!(x instanceof String s) || s.isEmpty() || s.substring(0, s.length() - 1).contains("*")) {
                        ok = false;
                        break;
                    }
                    out.add(s);
                }
            }
            if (!ok) throw new IllegalArgumentException(what + " must be a non-empty list of names, each with at most one trailing *");
            return out;
        }

        @SuppressWarnings("unchecked")
        Role(String name, Object def) {
            if (name.isEmpty() || !(def instanceof Map)) throw new IllegalArgumentException("role '" + name + "' must be an object");
            Map<String, Object> v = (Map<String, Object>) def;
            for (String k : v.keySet())
                // a misspelt key must not silently loosen a role
                if (!KEYS.contains(k)) throw new IllegalArgumentException("role '" + name + "': unknown field: " + k);
            this.name = name;
            if (!(v.get("members") instanceof List<?> ms) || ms.isEmpty()) throw new IllegalArgumentException("role '" + name + "': members must be a non-empty list of {type, id}");
            for (Object m : ms) {
                if (!(m instanceof Map<?, ?> mm) || !Cedar.validType(mm.get("type")) || !(mm.get("id") instanceof String))
                    throw new IllegalArgumentException("role '" + name + "': each member must be {type, id}");
                members.add(new Cedar.Entity((String) mm.get("type"), (String) mm.get("id")));
            }
            if (!v.containsKey("cap")) throw new IllegalArgumentException("role '" + name + "': cap is required");
            cap = Tokens.Cap.fromJson(v.get("cap"));
            cap.validate();
            if (v.containsKey("max_ttl")) {
                if (!(v.get("max_ttl") instanceof Long t) || t <= 0) throw new IllegalArgumentException("role '" + name + "': max_ttl must be a positive integer");
                maxTtl = t;
            } else {
                maxTtl = null;
            }
            tasks = v.containsKey("tasks") ? patternList(v.get("tasks"), "role '" + name + "': tasks") : null;
            agents = v.containsKey("agents") ? patternList(v.get("agents"), "role '" + name + "': agents") : null;
            if (v.containsKey("bindings") && !(v.get("bindings") instanceof Map)) throw new IllegalArgumentException("role '" + name + "': bindings must be an object");
            bindings = v.get("bindings") instanceof Map ? (Map<String, Object>) v.get("bindings") : new LinkedHashMap<>();
        }
    }

    static String read(Path p) {
        try {
            return Files.readString(p, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new EngineException("bundle_io", p + ": " + e.getMessage());
        }
    }

    static String digest(Path p) {
        return Crypto.sha256Hex(read(p).replace("\r\n", "\n"));
    }

    /** Relative path -> sha256 for every file that defines behaviour. */
    static Map<String, Object> manifest(Path dir) {
        Map<String, Object> files = new TreeMap<>();
        if (!Files.exists(dir.resolve("policies.json")))
            throw new EngineException("bundle_io", dir.resolve("policies.json") + ": missing. This port loads compiled policies; run `smartdelegate bundle compile` (Rust port) on the .cedar sources");
        files.put("policies.json", digest(dir.resolve("policies.json")));
        for (String name : List.of("entities.json", "catalog.json", "roles.json"))
            if (Files.exists(dir.resolve(name))) files.put(name, digest(dir.resolve(name)));
        return files;
    }

    static String versionOf(Map<String, Object> files) {
        return Crypto.sha256Hex(Json.canon(files));
    }

    static Map<String, Object> sign(Path dir, String privateB64) {
        Map<String, Object> files = manifest(dir);
        String version = versionOf(files);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("files", files);
        payload.put("version", version);
        byte[] sig = Crypto.sign(Crypto.privateKey(privateB64), Json.canon(payload).getBytes(StandardCharsets.UTF_8));
        Map<String, Object> out = new LinkedHashMap<>(payload);
        out.put("key_id", Crypto.keyId(Crypto.publicFromSeed(Crypto.seedOf(privateB64))));
        out.put("alg", "Ed25519");
        out.put("signature", Base64.getEncoder().encodeToString(sig));
        try {
            Files.writeString(dir.resolve("bundle.sig.json"), Json.write(out), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new EngineException("bundle_io", e.getMessage());
        }
        return out;
    }

    private static void verifySignature(Path dir, Map<String, Object> files, String publicB64) {
        Path p = dir.resolve("bundle.sig.json");
        if (!Files.exists(p)) throw new EngineException("bundle_unsigned", "a signed bundle is required, but bundle.sig.json is missing");
        Map<String, Object> sig;
        byte[] raw;
        try {
            sig = Json.parseObject(read(p));
            raw = Base64.getDecoder().decode((String) sig.get("signature"));
        } catch (RuntimeException e) {
            if (e instanceof EngineException) throw e;
            throw new EngineException("bundle_signature", "bundle.sig.json is malformed");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("files", sig.get("files"));
        payload.put("version", sig.get("version"));
        String canon;
        try {
            canon = Json.canon(payload);
        } catch (IllegalArgumentException e) {
            throw new EngineException("bundle_signature", "bundle.sig.json is malformed");
        }
        if (!Crypto.verify(Crypto.publicKey(Crypto.publicRaw(publicB64)), canon.getBytes(StandardCharsets.UTF_8), raw))
            throw new EngineException("bundle_signature", "bundle signature does not verify with the configured key");
        if (!files.equals(sig.get("files"))) throw new EngineException("bundle_signature", "bundle files changed after signing");
    }

    /** {@code publicKey}: when set, the bundle must carry a valid signature by that key or loading fails. */
    @SuppressWarnings("unchecked")
    Bundle(Path dir, String publicKey) {
        this.dir = dir;
        Map<String, Object> files = manifest(dir);
        this.version = versionOf(files);
        if (publicKey != null) {
            verifySignature(dir, files, publicKey);
            signedBy = Crypto.keyId(Crypto.publicRaw(publicKey));
        }
        Map<String, Object> doc;
        Map<String, Object> compiled;
        try {
            doc = Json.parseObject(read(dir.resolve("policies.json")));
            compiled = (Map<String, Object>) doc.get("policies");
            if (compiled == null) throw new IllegalArgumentException("no 'policies' object");
        } catch (EngineException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new EngineException("policy_parse", "policies.json: " + e.getMessage());
        }
        // policies.json records the hash of each .cedar file it was compiled
        // from, so a source edited (or added) without recompiling is noticed.
        Map<String, Object> sources = doc.get("sources") instanceof Map ? (Map<String, Object>) doc.get("sources") : Map.of();
        Map<String, Object> onDisk = new TreeMap<>();
        if (Files.isDirectory(dir.resolve("policies"))) {
            try (Stream<Path> s = Files.list(dir.resolve("policies"))) {
                for (Path p : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".cedar"))::iterator) onDisk.put("policies/" + p.getFileName(), digest(p));
            } catch (IOException e) {
                throw new EngineException("bundle_io", e.getMessage());
            }
        }
        if (!onDisk.isEmpty() && !onDisk.equals(new TreeMap<>(sources)))
            throw new EngineException("bundle_stale", "policies.json does not match the .cedar sources; run `smartdelegate bundle compile` from the Rust port");
        for (Map.Entry<String, Object> e : compiled.entrySet()) {
            try {
                policies.put(e.getKey(), new Cedar.Policy(e.getKey(), e.getValue()));
            } catch (Cedar.Unsupported | ClassCastException x) {
                throw new EngineException("policy_parse", "policies.json: " + e.getKey() + ": " + x.getMessage());
            }
        }

        List<Object> entities = new ArrayList<>();
        if (Files.exists(dir.resolve("entities.json"))) {
            try {
                entities = (List<Object>) Json.parse(read(dir.resolve("entities.json")));
                this.store = new Cedar.Store(entities);
                for (Object o : entities) {
                    Map<String, Object> e = (Map<String, Object>) o;
                    Map<String, Object> uid = (Map<String, Object>) e.get("uid");
                    attrs.put(uid.get("type") + "::" + uid.get("id"), e.get("attrs") instanceof Map ? e.get("attrs") : new LinkedHashMap<String, Object>());
                }
            } catch (EngineException e) {
                throw e;
            } catch (RuntimeException e) {
                throw new EngineException("entities_parse", String.valueOf(e.getMessage()));
            }
        } else {
            this.store = new Cedar.Store();
        }

        if (Files.exists(dir.resolve("catalog.json"))) {
            try {
                Map<String, Object> cat = Json.parseObject(read(dir.resolve("catalog.json")));
                Map<String, Object> resources = cat.get("resources") instanceof Map ? (Map<String, Object>) cat.get("resources") : Map.of();
                for (Map.Entry<String, Object> r : resources.entrySet()) {
                    Map<String, Object> rdef = (Map<String, Object>) r.getValue();
                    if (!Cedar.validType(rdef.get("entity_type"))) throw new IllegalArgumentException(r.getKey() + ": entity_type is missing or malformed");
                    Map<String, Object> fields = new TreeMap<>(Json.BY_CODE_POINT);
                    Map<String, Object> fdefs = rdef.get("fields") instanceof Map ? (Map<String, Object>) rdef.get("fields") : Map.of();
                    for (Map.Entry<String, Object> f : fdefs.entrySet()) {
                        Map<String, Object> fdef = (Map<String, Object>) f.getValue();
                        Object mask = fdef.get("mask");
                        if (mask != null && !"drop".equals(mask) && !"redact".equals(mask)) throw new IllegalArgumentException(r.getKey() + "." + f.getKey() + ": mask must be 'drop' or 'redact'");
                        Map<String, Object> clean = new LinkedHashMap<>();
                        clean.put("labels", fdef.get("labels") instanceof List ? fdef.get("labels") : new ArrayList<>());
                        clean.put("mask", mask);
                        fields.put(f.getKey(), clean);
                    }
                    Map<String, Object> def = new LinkedHashMap<>();
                    def.put("entity_type", rdef.get("entity_type"));
                    def.put("fields", fields);
                    catalog.put(r.getKey(), def);
                }
            } catch (EngineException e) {
                throw e;
            } catch (RuntimeException e) {
                throw new EngineException("catalog_parse", String.valueOf(e.getMessage()));
            }
        }

        if (Files.exists(dir.resolve("roles.json"))) {
            try {
                Object doc2 = Json.parse(read(dir.resolve("roles.json")));
                if (!(doc2 instanceof Map<?, ?> dm) || !(dm.get("roles") instanceof Map<?, ?> rm)) throw new IllegalArgumentException("expected {\"roles\": {...}}");
                for (Map.Entry<?, ?> e : rm.entrySet()) roles.put((String) e.getKey(), new Role((String) e.getKey(), e.getValue()));
            } catch (EngineException e) {
                throw new EngineException("roles_parse", "roles.json: " + e.detail());
            } catch (RuntimeException | StackOverflowError e) {
                throw new EngineException("roles_parse", "roles.json: " + e.getMessage());
            }
        }
    }
}
