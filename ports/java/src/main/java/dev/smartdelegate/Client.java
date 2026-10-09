package dev.smartdelegate;

import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Thin client for the SmartDelegate decision daemon ({@code smartdelegate serve}).
 * Works from Java and Kotlin; needs Java 11+ and no dependencies.
 *
 * <pre>
 * Client iam = new Client("http://127.0.0.1:8181", pepKey, null);
 * Map&lt;String,Object&gt; d = iam.require(token, "read", "crm.customer", "c-1", null);
 * Object safe = iam.applyObligations(d, record);   // mask before the model sees it
 * </pre>
 */
public final class Client {
    private static final Map<String, String[]> ROUTES = new LinkedHashMap<>();

    static {
        ROUTES.put("authorize", new String[] {"POST", "/v1/authorize", "pep"});
        ROUTES.put("filter", new String[] {"POST", "/v1/filter", "pep"});
        ROUTES.put("explain", new String[] {"POST", "/v1/explain", "pep"});
        ROUTES.put("apply_obligations", new String[] {"POST", "/v1/obligations/apply", "pep"});
        ROUTES.put("inspect_token", new String[] {"POST", "/v1/token/inspect", "pep"});
        ROUTES.put("info", new String[] {"GET", "/v1/info", "pep"});
        ROUTES.put("exchange_token", new String[] {"POST", "/v1/token", ""});
        ROUTES.put("issue_token", new String[] {"POST", "/v1/token", "admin"});
        ROUTES.put("revoke", new String[] {"POST", "/v1/admin/revoke", "admin"});
        ROUTES.put("approve", new String[] {"POST", "/v1/admin/approve", "admin"});
        ROUTES.put("reload", new String[] {"POST", "/v1/admin/reload", "admin"});
        ROUTES.put("approvals", new String[] {"GET", "/v1/admin/approvals", "admin"});
        ROUTES.put("audit_verify", new String[] {"GET", "/v1/admin/audit/verify", "admin"});
        ROUTES.put("audit_tail", new String[] {"GET", "/v1/admin/audit/tail", "admin"});
    }

    private final String url;
    private final String pepKey;
    private final String adminKey;
    private final HttpClient http;

    public Client(String url, String pepKey, String adminKey) {
        this.url = url.replaceAll("/+$", "");
        this.pepKey = pepKey != null ? pepKey : adminKey;
        this.adminKey = adminKey;
        // never route decision traffic through an environment proxy
        this.http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5)).proxy(ProxySelector.of(null)).build();
    }

    /** Raw operation: the engine's JSON result, including {@code ok:false} errors. */
    public Map<String, Object> call(String op, Map<String, Object> payload) {
        String[] route = ROUTES.get(op);
        if (route == null) {
            return error("unknown_op", "no operation named '" + op + "'");
        }
        String path = route[1];
        if (op.equals("audit_tail") && payload.get("n") != null) path += "?n=" + ((Number) payload.get("n")).longValue();
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url + path)).timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json");
        String key = route[2].equals("pep") ? pepKey : route[2].equals("admin") ? adminKey : null;
        if (op.equals("issue_token") && payload.get("id_token") != null) key = null;
        if (key != null) b.header("Authorization", "Bearer " + key);
        b = route[0].equals("POST") ? b.POST(HttpRequest.BodyPublishers.ofString(Json.write(payload))) : b.GET();
        HttpResponse<String> resp;
        try {
            resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SmartDelegateException("daemon_unreachable", "interrupted");
        } catch (java.io.IOException e) {
            // an unreachable decision point is never an allow
            throw new SmartDelegateException("daemon_unreachable", String.valueOf(e.getMessage()));
        }
        try {
            return Json.parseObject(resp.body());
        } catch (RuntimeException e) {
            return error("http_error", "HTTP " + resp.statusCode());
        }
    }

    private static Map<String, Object> error(String code, String message) {
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("code", code);
        err.put("message", message);
        err.put("rule", EngineException.ruleId(code));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", false);
        out.put("error", err);
        return out;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> ok(String op, Map<String, Object> payload) {
        Map<String, Object> r = call(op, payload);
        if (!Boolean.TRUE.equals(r.get("ok"))) {
            Map<String, Object> e = r.get("error") instanceof Map ? (Map<String, Object>) r.get("error") : Map.of();
            throw new SmartDelegateException(String.valueOf(e.getOrDefault("code", "error")), String.valueOf(e.getOrDefault("message", "unknown error")));
        }
        return r;
    }

    private static Map<String, Object> request(String token, String action, String resource, String id, Map<String, Object> context) {
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("path", resource);
        res.put("id", id != null ? id : "any");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token);
        body.put("action", action);
        body.put("resource", res);
        if (context != null) body.put("context", context);
        return body;
    }

    /** Decide. Inspect {@code effect}; a deny is a normal result. */
    public Map<String, Object> authorize(String token, String action, String resource, String id, Map<String, Object> context) {
        return ok("authorize", request(token, action, resource, id, context));
    }

    /** Decide, and throw {@link DeniedException} unless the effect is allow. */
    public Map<String, Object> require(String token, String action, String resource, String id, Map<String, Object> context) {
        Map<String, Object> d = authorize(token, action, resource, id, context);
        if (!"allow".equals(d.get("effect"))) throw new DeniedException(d);
        return d;
    }

    /** Decide and mask {@code data} in one call. {@code strict} rejects input that carries a denied field. */
    public Map<String, Object> filter(String token, String action, String resource, String id, Object data, boolean strict, Map<String, Object> context) {
        Map<String, Object> body = request(token, action, resource, id, context);
        body.put("data", data);
        if (strict) body.put("strict", true);
        return ok("filter", body);
    }

    /** Mask data that arrived after the decision (a tool result). Returns the masked data. */
    public Object applyObligations(Map<String, Object> decision, Object data) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("obligations", decision.get("obligations"));
        body.put("data", data);
        body.put("decision_id", decision.get("decision_id"));
        return ok("apply_obligations", body).get("data");
    }

    public Map<String, Object> exchangeToken(String subjectToken, String actor, Map<String, Object> cap, Integer ttlSeconds) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("subject_token", subjectToken);
        body.put("actor", actor);
        if (cap != null) body.put("cap", cap);
        if (ttlSeconds != null) body.put("ttl", ttlSeconds);
        return ok("exchange_token", body);
    }

    public Map<String, Object> issueToken(String user, String agent, Map<String, Object> cap) {
        return issueToken(user, agent, null, cap, null, null);
    }

    /**
     * Issue a token under a role the user holds. The token never carries more
     * than the role allows. {@code cap} (a narrower capability), {@code task}
     * and {@code groups} (live group membership: names or {type, id}) may be
     * null. The result's {@code role} is the role, or null without one.
     */
    public Map<String, Object> issueToken(String user, String agent, String role, Map<String, Object> cap, String task, List<?> groups) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("user", user);
        body.put("agent", agent);
        if (role != null) body.put("role", role);
        if (cap != null) body.put("cap", cap);
        if (task != null) body.put("task", task);
        if (groups != null) body.put("groups", groups);
        return ok("issue_token", body);
    }

    /** The role a decision or a token result was made under, or null. */
    @SuppressWarnings("unchecked")
    public static String roleOf(Map<String, Object> result) {
        Object p = result.get("principal");
        Object r = p instanceof Map ? ((Map<String, Object>) p).get("role") : result.get("role");
        return r instanceof String ? (String) r : null;
    }

    public Map<String, Object> approve(String approvalId, String by) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("approval_id", approvalId);
        body.put("by", by);
        return ok("approve", body);
    }

    /**
     * End every token already issued for this human, sub-agent tokens
     * included. Use it when a person is offboarded or loses a role.
     * {@code by} may be null. The result has {@code revoked_user} and {@code issued_up_to}.
     */
    public Map<String, Object> revokeUser(String user, String by) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("user", user);
        if (by != null) body.put("by", by);
        return ok("revoke", body);
    }

    public Map<String, Object> revoke(String tokenId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token_id", tokenId);
        return ok("revoke", body);
    }
}
