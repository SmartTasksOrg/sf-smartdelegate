package dev.smartdelegate;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Capability tokens: EdDSA-signed JWTs with an RFC 8693 {@code act}
 * delegation chain and a {@code cap} claim that can only be narrowed on each
 * hop. A port of src/sf_smartdelegate/tokens.py.
 */
final class Tokens {
    private Tokens() {}

    static final String AUDIENCE = "smartdelegate";
    private static final Base64.Encoder B64U = Base64.getUrlEncoder().withoutPadding();

    static String b64u(byte[] b) {
        return B64U.encodeToString(b);
    }

    private static final java.util.regex.Pattern B64U_TEXT = java.util.regex.Pattern.compile("[A-Za-z0-9_-]+");

    /**
     * Strict: exactly the URL-safe alphabet, no padding, nothing skipped, so
     * one token has one spelling. Throws IllegalArgumentException otherwise.
     */
    static byte[] b64uDec(Object text) {
        if (!(text instanceof String s) || !B64U_TEXT.matcher(s).matches() || s.length() % 4 == 1) throw new IllegalArgumentException("not base64url");
        return Base64.getUrlDecoder().decode(s);
    }

    // ---- capability ----------------------------------------------------------

    static final class Cap {
        final List<String> actions, resources, denyLabels, denyFields;
        final Map<String, Long> budget = new LinkedHashMap<>();

        Cap(List<String> actions, List<String> resources, List<String> denyLabels, List<String> denyFields, Map<String, Long> budget) {
            this.actions = actions;
            this.resources = resources;
            this.denyLabels = denyLabels;
            this.denyFields = denyFields;
            if (budget != null) this.budget.putAll(budget);
        }

        private static List<String> strings(Object v, String what) {
            List<String> out = new ArrayList<>();
            if (v == null) return out;
            if (!(v instanceof List<?> l)) throw new EngineException("invalid_cap", what + " must be a list of strings");
            for (Object x : l) {
                if (!(x instanceof String s)) throw new EngineException("invalid_cap", what + " must be a list of strings");
                out.add(s);
            }
            return out;
        }

        static Cap fromJson(Object v) {
            if (!(v instanceof Map<?, ?> m)) throw new EngineException("invalid_cap", "cap must be an object");
            for (Object k : m.keySet())
                // a misspelt key must not silently become "no restriction"
                if (!Set.of("actions", "resources", "deny_labels", "deny_fields", "budget").contains(k)) throw new EngineException("invalid_cap", "unknown cap field: " + k);
            Map<String, Long> budget = new LinkedHashMap<>();
            Object b = m.get("budget");
            if (b != null) {
                if (!(b instanceof Map<?, ?> bm)) throw new EngineException("invalid_cap", "cap.budget must map currency to an integer amount in minor units");
                for (Map.Entry<?, ?> e : bm.entrySet()) {
                    if (!(e.getKey() instanceof String) || !(e.getValue() instanceof Long)) throw new EngineException("invalid_cap", "cap.budget must map currency to an integer amount in minor units");
                    budget.put((String) e.getKey(), (Long) e.getValue());
                }
            }
            return new Cap(strings(m.get("actions"), "cap.actions"), strings(m.get("resources"), "cap.resources"),
                    strings(m.get("deny_labels"), "cap.deny_labels"), strings(m.get("deny_fields"), "cap.deny_fields"), budget);
        }

        static Cap unrestricted() {
            return new Cap(List.of("*"), List.of("*"), List.of(), List.of(), null);
        }

        Map<String, Object> toJson() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("actions", actions);
            out.put("resources", resources);
            out.put("deny_labels", denyLabels);
            out.put("deny_fields", denyFields);
            out.put("budget", new LinkedHashMap<String, Object>(budget));
            return out;
        }

        void validate() {
            List<String> all = new ArrayList<>(actions);
            all.addAll(resources);
            for (String p : all)
                if (p.isEmpty() || p.substring(0, p.length() - 1).contains("*")) throw new EngineException("invalid_cap", "pattern '" + p + "': only one trailing * is allowed");
            for (long v : budget.values()) if (v < 0) throw new EngineException("invalid_cap", "budget cannot be negative");
        }

        static boolean matches(String pattern, String s) {
            return pattern.endsWith("*") ? s.startsWith(pattern.substring(0, pattern.length() - 1)) : pattern.equals(s);
        }

        /** Does parent cover every string that child covers? */
        static boolean covers(String parent, String child) {
            if (parent.endsWith("*")) {
                String pp = parent.substring(0, parent.length() - 1);
                String c = child.endsWith("*") ? child.substring(0, child.length() - 1) : child;
                return c.startsWith(pp);
            }
            return !child.endsWith("*") && parent.equals(child);
        }

        boolean allowsAction(String action) {
            return actions.stream().anyMatch(p -> matches(p, action));
        }

        boolean allowsResource(String path, String id) {
            String s = path + "/" + id;
            return resources.stream().anyMatch(p -> matches(p, s));
        }

        /** Throws {@code widening} unless this grants nothing the parent does not. */
        void checkNarrowerThan(Cap parent) {
            for (String a : actions)
                if (parent.actions.stream().noneMatch(p -> covers(p, a))) throw new EngineException("widening", "action '" + a + "' is not covered by the parent token");
            for (String r : resources)
                if (parent.resources.stream().noneMatch(p -> covers(p, r))) throw new EngineException("widening", "resource '" + r + "' is not covered by the parent token");
            for (String l : parent.denyLabels)
                if (!denyLabels.contains(l)) throw new EngineException("widening", "label '" + l + "' is denied by the parent and must stay denied");
            for (String f : parent.denyFields)
                if (!denyFields.contains(f)) throw new EngineException("widening", "field '" + f + "' is denied by the parent and must stay denied");
            for (Map.Entry<String, Long> e : budget.entrySet()) {
                Long p = parent.budget.get(e.getKey());
                if (p == null) throw new EngineException("widening", "the parent token has no " + e.getKey() + " budget to pass on");
                if (e.getValue() > p) throw new EngineException("widening", "budget " + e.getValue() + " " + e.getKey() + " exceeds the parent's " + p);
            }
        }
    }

    // ---- claims ----------------------------------------------------------------

    /** RFC 8693 actor chain: the current actor is outermost. */
    static Map<String, Object> actFor(List<String> chain) {
        Map<String, Object> act = null;
        for (String agent : chain) {
            Map<String, Object> next = new LinkedHashMap<>();
            next.put("sub", "agent:" + agent);
            if (act != null) next.put("act", act);
            act = next;
        }
        return act;
    }

    /** Agents root-first. */
    static List<String> chainOf(Map<String, Object> claims) {
        List<String> out = new ArrayList<>();
        Object cur = claims.get("act");
        while (cur instanceof Map<?, ?> m && m.get("sub") instanceof String sub) {
            out.add(0, sub.startsWith("agent:") ? sub.substring(6) : sub);
            cur = m.get("act");
        }
        return out;
    }

    static String userOf(Map<String, Object> claims) {
        String sub = String.valueOf(claims.getOrDefault("sub", ""));
        return sub.startsWith("user:") ? sub.substring(5) : sub;
    }

    static final class Keys {
        private PrivateKey priv;
        String kid, publicB64;
        private final Map<String, PublicKey> verifiers = new HashMap<>();

        Keys(String privateB64, List<String> trustedPublicB64) {
            if (privateB64 != null) {
                priv = Crypto.privateKey(privateB64);
                byte[] raw = Crypto.publicFromSeed(Crypto.seedOf(privateB64));
                kid = Crypto.keyId(raw);
                publicB64 = Base64.getEncoder().encodeToString(raw);
                verifiers.put(kid, Crypto.publicKey(raw));
            }
            for (String b : trustedPublicB64) {
                byte[] raw = Crypto.publicRaw(b);
                verifiers.put(Crypto.keyId(raw), Crypto.publicKey(raw));
            }
        }

        boolean canSign() {
            return priv != null;
        }

        String sign(Map<String, Object> claims) {
            if (priv == null) throw new EngineException("no_signing_key", "this engine can verify tokens but not issue them");
            Map<String, Object> header = new LinkedHashMap<>();
            header.put("typ", "JWT");
            header.put("alg", "EdDSA");
            header.put("kid", kid);
            String signingInput = b64u(Json.write(header).getBytes(StandardCharsets.UTF_8)) + "." + b64u(Json.write(claims).getBytes(StandardCharsets.UTF_8));
            return signingInput + "." + b64u(Crypto.sign(priv, signingInput.getBytes(StandardCharsets.UTF_8)));
        }

        /** Signature, issuer, audience and shape. Time and revocation belong to the engine. Throws IllegalArgumentException(reason). */
        Map<String, Object> verify(String token, String issuer) {
            String[] parts = token.split("\\.", -1);
            Map<String, Object> header;
            byte[] sig;
            try {
                if (parts.length != 3) throw new IllegalArgumentException();
                header = Json.parseObject(new String(b64uDec(parts[0]), StandardCharsets.UTF_8));
                sig = b64uDec(parts[2]);
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("token is not a JWT");
            }
            if (!"EdDSA".equals(header.get("alg"))) throw new IllegalArgumentException("token algorithm is not EdDSA");
            if (!(header.get("kid") instanceof String k)) throw new IllegalArgumentException("token has no key id");
            PublicKey key = verifiers.get(k);
            if (key == null) throw new IllegalArgumentException("token was signed by an unknown key");
            if (!Crypto.verify(key, (parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8), sig)) throw new IllegalArgumentException("token rejected: bad signature");
            Map<String, Object> claims;
            try {
                claims = Json.parseObject(new String(b64uDec(parts[1]), StandardCharsets.UTF_8));
                for (String f : List.of("iss", "aud", "sub", "jti")) if (!(claims.get(f) instanceof String)) throw new IllegalArgumentException();
                for (String f : List.of("iat", "exp")) if (!(claims.get(f) instanceof Long)) throw new IllegalArgumentException();
                if (!(claims.get("act") instanceof Map)) throw new IllegalArgumentException();
                Object anc = claims.get("anc");
                if (anc == null) claims.put("anc", new ArrayList<>());
                else if (!(anc instanceof List<?> l) || l.stream().anyMatch(x -> !(x instanceof String))) throw new IllegalArgumentException();
                if (claims.containsKey("role") && !(claims.get("role") instanceof String r && !r.isEmpty())) throw new IllegalArgumentException();
                if (claims.containsKey("grp")) {
                    if (!(claims.get("grp") instanceof List<?> gl)) throw new IllegalArgumentException();
                    for (Object g : gl)
                        if (!(g instanceof Map<?, ?> gm && gm.get("type") instanceof String && gm.get("id") instanceof String)) throw new IllegalArgumentException();
                }
                if (claims.containsKey("lim")) {
                    // ancestor budgets: {token id: {currency: non-negative integer}}
                    if (!(claims.get("lim") instanceof Map<?, ?> lim)) throw new IllegalArgumentException();
                    for (Object b : lim.values()) {
                        if (!(b instanceof Map<?, ?> bm)) throw new IllegalArgumentException();
                        for (Object v : bm.values()) if (!(v instanceof Long l) || l < 0) throw new IllegalArgumentException();
                    }
                }
                claims.put("cap", Cap.fromJson(claims.get("cap")).toJson());
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("token rejected: malformed claims");
            }
            if (!AUDIENCE.equals(claims.get("aud"))) throw new IllegalArgumentException("token rejected: wrong audience");
            if (!issuer.equals(claims.get("iss"))) throw new IllegalArgumentException("token rejected: wrong issuer");
            return claims;
        }
    }

    // ---- OIDC ID tokens ------------------------------------------------------

    private static BigInteger num(Object b64) {
        return new BigInteger(1, b64uDec(b64));
    }

    private static boolean verifyJws(String alg, Map<String, Object> jwk, byte[] input, byte[] sig) throws Exception {
        Object kty = jwk.get("kty");
        if (Set.of("RS256", "RS384", "RS512").contains(alg) && "RSA".equals(kty)) {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(num(jwk.get("n")), num(jwk.get("e"))));
            Signature s = Signature.getInstance("SHA" + alg.substring(2) + "withRSA");
            s.initVerify(key);
            s.update(input);
            return s.verify(sig);
        }
        if (Set.of("ES256", "ES384").contains(alg) && "EC".equals(kty)) {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(alg.equals("ES256") ? "secp256r1" : "secp384r1"));
            PublicKey key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(num(jwk.get("x")), num(jwk.get("y"))), params.getParameterSpec(ECParameterSpec.class)));
            Signature s = Signature.getInstance("SHA" + alg.substring(2) + "withECDSAinP1363Format");
            s.initVerify(key);
            s.update(input);
            return s.verify(sig);
        }
        if ("EdDSA".equals(alg) && "OKP".equals(kty) && "Ed25519".equals(jwk.get("crv"))) return Crypto.verify(Crypto.publicKey(b64uDec(jwk.get("x"))), input, sig);
        throw new IllegalArgumentException("unsupported signing algorithm");
    }

    /** Verify an OIDC ID token against a static JWKS and return its claims. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> verifyIdToken(String idToken, Map<String, Object> jwks, String issuer, String audience, long now) {
        String[] parts = idToken.split("\\.", -1);
        Map<String, Object> header;
        byte[] sig;
        String alg;
        try {
            if (parts.length != 3) throw new IllegalArgumentException();
            header = Json.parseObject(new String(b64uDec(parts[0]), StandardCharsets.UTF_8));
            sig = b64uDec(parts[2]);
            alg = (String) header.get("alg");
            if (alg == null) throw new IllegalArgumentException();
        } catch (RuntimeException e) {
            throw new EngineException("id_token_invalid", "not a JWT");
        }
        List<Map<String, Object>> keys = new ArrayList<>();
        if (jwks.get("keys") instanceof List<?> l) for (Object k : l) if (k instanceof Map) keys.add((Map<String, Object>) k);
        Object kid = header.get("kid");
        Map<String, Object> jwk = null;
        if (kid != null) {
            for (Map<String, Object> k : keys) if (kid.equals(k.get("kid"))) { jwk = k; break; }
        } else if (keys.size() == 1) {
            jwk = keys.get(0);
        }
        if (jwk == null) throw new EngineException("id_token_invalid", "no matching key in the JWKS");
        boolean ok;
        try {
            ok = verifyJws(alg, jwk, (parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8), sig);
        } catch (Exception e) {
            throw new EngineException("id_token_invalid", e instanceof IllegalArgumentException && e.getMessage() != null ? e.getMessage() : "key or signature is malformed");
        }
        if (!ok) throw new EngineException("id_token_invalid", "signature does not verify");
        Map<String, Object> claims;
        try {
            claims = Json.parseObject(new String(b64uDec(parts[1]), StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw new EngineException("id_token_invalid", "malformed claims");
        }
        if (!issuer.equals(claims.get("iss"))) throw new EngineException("id_token_invalid", "wrong issuer");
        Object aud = claims.get("aud");
        if (!(audience.equals(aud) || (aud instanceof List<?> al && al.contains(audience)))) throw new EngineException("id_token_invalid", "wrong audience");
        // OIDC Core 3.1.3.7: a token issued to another client is not ours even when
        // our client id is among its audiences (access tokens of other clients are)
        if (claims.containsKey("azp") && !audience.equals(claims.get("azp"))) throw new EngineException("id_token_invalid", "issued to another client (azp)");
        if (aud instanceof List<?> many && many.size() > 1 && !claims.containsKey("azp")) throw new EngineException("id_token_invalid", "several audiences and no azp claim");
        if (!(claims.get("exp") instanceof Long exp)) throw new EngineException("id_token_invalid", "no exp claim");
        if (exp <= now) throw new EngineException("id_token_invalid", "ID token has expired");
        if (claims.get("nbf") instanceof Long nbf && nbf > now + 60) throw new EngineException("id_token_invalid", "ID token is not valid yet");
        return claims;
    }
}
