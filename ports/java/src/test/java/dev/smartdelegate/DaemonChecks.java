package dev.smartdelegate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static dev.smartdelegate.Conformance.ADMIN;
import static dev.smartdelegate.Conformance.PEP;
import static dev.smartdelegate.Conformance.check;
import static dev.smartdelegate.Conformance.passed;

/**
 * Tests of the Java daemon ({@link Server}) and command line ({@link Cli}),
 * run by {@link Conformance} after its own suites:
 *
 * 1. the shared vectors over REST: Java client, Java daemon;
 * 2. keys, status codes, the body limit, error bodies;
 * 3. many threads against one daemon, and against two engines on one state
 *    directory: a budget is never exceeded and the audit chain stays valid
 *    (also in the reference's eyes);
 * 4. the command line: commands, configuration, exit codes, and tokens,
 *    bundles and audit logs exchanged with the reference command line;
 * 5. OIDC with ID tokens minted here (RS256, JDK): `reload` re-reads
 *    idp.jwks_file, azp, revoked users, nested group claims;
 * 6. the launcher script (only with -Dsmartdelegate.launcher=PATH): `serve`
 *    prints its URL first, answers, and stops on SIGTERM.
 *
 * Everything that can hang has a timeout; every daemon started is stopped.
 */
final class DaemonChecks {
    private DaemonChecks() {}

    static final String FULL = "{\"actions\":[\"read\",\"create\",\"update\"],\"resources\":[\"crm.customer/*\",\"billing.refund/*\"],\"budget\":{\"EUR\":20000}}";

    @SuppressWarnings("unchecked")
    static Map<String, Object> err(Map<String, Object> r) {
        return r.get("error") instanceof Map ? (Map<String, Object>) r.get("error") : Map.of();
    }

    // ---- 1. vectors over REST --------------------------------------------------

    @SuppressWarnings("unchecked")
    static void restVectors(Path root) throws Exception {
        int total = 0, bad = 0;
        for (Map<String, Object> c : Conformance.cases(root)) {
            Path state = Files.createTempDirectory("smartdelegate-java-d-");
            Map<String, Object> cfg = Conformance.config(root, state);
            if (c.get("_config") != null) cfg.putAll((Map<String, Object>) c.get("_config"));
            try (Engine engine = new Engine(cfg); Server server = Server.listen(engine, "127.0.0.1:0", ADMIN, PEP)) {
                Client client = new Client(server.url(), PEP, ADMIN);
                List<String> failures = Conformance.runCase(client::call, c);
                total++;
                if (!failures.isEmpty()) { bad++; System.out.println("FAIL " + c.get("_suite") + ": " + c.get("name") + "\n  " + String.join("\n  ", failures)); }
            } finally {
                Conformance.rm(state);
            }
        }
        Conformance.report("java daemon conformance (REST, java daemon, java client)", total, bad);
    }

    // ---- 2. keys, status codes, body limit ---------------------------------------

    static final HttpClient HTTP = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5)).proxy(ProxySelector.of(null)).build();

    record Answer(int status, Map<String, Object> body, String contentType) {
        String code() {
            return String.valueOf(err(body).get("code"));
        }
    }

    /** One request. {@code key}: the bearer key, or null for no Authorization header. */
    static Answer http(String url, String method, String path, String key, byte[] body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url + path)).timeout(Duration.ofSeconds(20));
        if (key != null) b.header("Authorization", key);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        HttpResponse<String> r = HTTP.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        Map<String, Object> doc;
        try {
            doc = Json.parseObject(r.body());
        } catch (RuntimeException e) {
            throw new AssertionError(method + " " + path + ": HTTP " + r.statusCode() + " with a body that is not a JSON object: " + r.body());
        }
        return new Answer(r.statusCode(), doc, r.headers().firstValue("Content-Type").orElse(null));
    }

    static Answer post(String url, String path, String key, String json) throws Exception {
        return http(url, "POST", path, key, json.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Raw bytes in, raw answer out, with a socket timeout: for requests an
     * HTTP client will not send. Reads one answer (headers and Content-Length
     * bytes). With {@code untilClosed}, then waits for the daemon to close the
     * connection, at most {@code closeWithinMillis}; returns null if it stays open.
     */
    static String raw(Server server, String request, boolean untilClosed, int closeWithinMillis) throws IOException {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", server.port()), 5000);
            s.setSoTimeout(10_000);
            OutputStream out = s.getOutputStream();
            out.write(request.getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            InputStream in = s.getInputStream();
            byte[] chunk = new byte[4096];
            String text = "";
            try {
                for (int n; (n = in.read(chunk)) >= 0; ) {
                    buf.write(chunk, 0, n);
                    text = buf.toString(StandardCharsets.ISO_8859_1);
                    Matcher m = Pattern.compile("(?i)\r\nContent-Length: *([0-9]+)\r\n").matcher(text);
                    int head = text.indexOf("\r\n\r\n");
                    if (head >= 0 && m.find() && text.length() >= head + 4 + Integer.parseInt(m.group(1))) break;
                }
            } catch (java.net.SocketTimeoutException e) {
                if (!untilClosed) throw e;   // no answer at all is fine only when the caller waits for the close
            }
            if (!untilClosed) return text;
            s.setSoTimeout(closeWithinMillis);
            try {
                while (in.read(chunk) >= 0) { }
                return text;
            } catch (java.net.SocketTimeoutException e) {
                return null;
            } catch (IOException e) {
                return text;   // reset: closed
            }
        }
    }

    static String raw(Server server, String request) throws IOException {
        return raw(server, request, false, 0);
    }

    @SuppressWarnings("unchecked")
    static void keysAndStatus(Path root) throws Exception {
        Path state = Files.createTempDirectory("smartdelegate-java-k-");
        Map<String, Object> cfg = Conformance.config(root, state);
        Map<String, Object> idp = new LinkedHashMap<>();
        idp.put("issuer", "https://idp.example.test");
        idp.put("audience", "smartdelegate-demo");
        idp.put("jwks_file", root.resolve("spec/conformance/oidc/jwks.json").toString());
        cfg.put("idp", idp);
        Map<String, Object> ids = Json.parseObject(Files.readString(root.resolve("spec/conformance/oidc/id_tokens.json")));
        String A = "Bearer " + ADMIN, P = "Bearer " + PEP;
        try (Engine engine = new Engine(cfg); Server server = Server.listen(engine, "127.0.0.1:0", ADMIN, PEP)) {
            String u = server.url();
            check(u.matches("http://127\\.0\\.0\\.1:[0-9]+") && server.port() > 0, "the daemon reports its URL: " + u);

            Answer h = http(u, "GET", "/healthz", null, null);
            check(h.status() == 200 && Boolean.TRUE.equals(h.body().get("ok")) && h.body().size() == 1 && "application/json".equals(h.contentType()), "/healthz needs no key: " + h);

            // pep routes: pep or admin key; admin routes: admin key only
            String[][] routes = {
                    {"GET", "/v1/info", "pep"}, {"POST", "/v1/authorize", "pep"}, {"POST", "/v1/filter", "pep"}, {"POST", "/v1/explain", "pep"},
                    {"POST", "/v1/obligations/apply", "pep"}, {"POST", "/v1/token/inspect", "pep"}, {"POST", "/v1/admin/revoke", "admin"},
                    {"POST", "/v1/admin/approve", "admin"}, {"POST", "/v1/admin/reload", "admin"}, {"GET", "/v1/admin/approvals", "admin"},
                    {"GET", "/v1/admin/audit/verify", "admin"}, {"GET", "/v1/admin/audit/tail", "admin"}};
            for (String[] r : routes) {
                byte[] body = r[0].equals("POST") ? "{}".getBytes(StandardCharsets.UTF_8) : null;
                String what = r[0] + " " + r[1];
                for (String bad : new String[] {null, "Bearer wrong-key-0123456789abcdef", "Bearer ", "bearer " + ADMIN, "Basic " + ADMIN, ADMIN, A + "x", A.substring(0, A.length() - 1), "Bearer " + ADMIN + " " + ADMIN}) {
                    Answer x = http(u, r[0], r[1], bad, body);
                    check(x.status() == 401 && x.code().equals("unauthorized") && Boolean.FALSE.equals(x.body().get("ok")), what + " with key [" + bad + "] is 401: " + x);
                }
                Answer withPep = http(u, r[0], r[1], P, body), withAdmin = http(u, r[0], r[1], A, body);
                if (r[2].equals("admin")) check(withPep.status() == 401 && withPep.code().equals("unauthorized"), what + " refuses the pep key: " + withPep);
                else check(withPep.status() != 401 && !withPep.code().equals("unauthorized"), what + " accepts the pep key: " + withPep);
                check(withAdmin.status() != 401 && !withAdmin.code().equals("unauthorized"), what + " accepts the admin key: " + withAdmin);
                // 200 exactly when the engine said ok
                check((withAdmin.status() == 200) == Boolean.TRUE.equals(withAdmin.body().get("ok")) && (withAdmin.status() == 200 || withAdmin.status() == 400), what + ": 200 for ok, 400 for an error: " + withAdmin);
                Answer other = http(u, r[0].equals("POST") ? "GET" : "POST", r[1], A, r[0].equals("POST") ? null : "{}".getBytes(StandardCharsets.UTF_8));
                check(other.status() == 404 && other.code().equals("not_found"), what + " with the other method is 404: " + other);
            }
            check(http(u, "GET", "/v1/info", "Bearer   " + PEP + "  ", null).status() == 200, "spaces around the key are ignored, as in the reference");
            Answer nf = http(u, "GET", "/v1/nope", A, null);
            check(nf.status() == 404 && nf.code().equals("not_found") && "application/json".equals(nf.contentType()), "an unknown path is a JSON 404: " + nf);
            check(http(u, "GET", "/v1/%69nfo", A, null).status() == 404, "paths are not percent-decoded");
            for (String m : new String[] {"PUT", "DELETE", "PATCH"}) {
                Answer x = http(u, m, "/v1/info", A, "{}".getBytes(StandardCharsets.UTF_8));
                check(x.status() == 501 && Boolean.FALSE.equals(x.body().get("ok")), m + " is 501 with a JSON error: " + x);
            }

            // bodies: parsed before the key is looked at, as in the reference
            for (String bad : new String[] {"{", "not json", "{\"a\":1,}", "[".repeat(100_000), "{\"a\":\"\\ud800", "{\"a\":+1}", "{\"a\":01}", "{\"a\":1.}", "{\"a\":.5}",
                    "{\"a\":\"x\ty\"}", "{\"a\":\"\\x\"}", "{\"a\":\"\\u12g4\"}", "{'a':1}", "{\"a\":1}{", "{\"a\":1}\u000b", "{\"a\":99999999999999999999}", "{\"a\":1e999}", "{\"a\":tru}"}) {
                Answer x = post(u, "/v1/authorize", null, bad);
                check(x.status() == 400 && x.code().equals("invalid_input") && "body is not JSON".equals(err(x.body()).get("message")), "a body that is not JSON is 400 invalid_input: " + x);
            }
            Answer notUtf8 = http(u, "POST", "/v1/authorize", P, new byte[] {'{', '"', 'a', '"', ':', '"', (byte) 0xff, '"', '}'});
            check(notUtf8.status() == 400 && "body is not JSON".equals(err(notUtf8.body()).get("message")), "a body that is not UTF-8 is refused: " + notUtf8);
            for (String notObject : new String[] {"[]", "\"x\"", "12", "null", "true"}) {
                Answer x = post(u, "/v1/authorize", P, notObject);
                check(x.status() == 400 && x.code().equals("invalid_input") && Boolean.FALSE.equals(x.body().get("ok")), "a body that is not an object is refused by the engine: " + x);
                Answer y = post(u, "/v1/token", null, notObject);
                check(y.status() == 401, "and cannot issue a token without the admin key: " + y);
            }
            Answer empty = post(u, "/v1/authorize", P, "  \n");
            check(empty.status() == 400 && empty.code().equals("invalid_input") && String.valueOf(err(empty.body()).get("message")).contains("action"), "a blank body is {}: " + empty);

            // /v1/token
            String issue = "{\"user\":\"alice\",\"agent\":\"support-bot\",\"cap\":" + FULL + "}";
            for (String key : new String[] {null, P, "Bearer nope"}) {
                Answer x = post(u, "/v1/token", key, issue);
                check(x.status() == 401 && x.body().get("token") == null, "issuing a root token needs the admin key (" + key + "): " + x);
            }
            Answer t = post(u, "/v1/token", A, issue);
            check(t.status() == 200 && t.body().get("token") instanceof String, "the admin key issues a token: " + t);
            String token = (String) t.body().get("token");
            Answer ex = post(u, "/v1/token", null, "{\"subject_token\":\"" + token + "\",\"actor\":\"refund-helper\",\"ttl\":300,\"cap\":{\"actions\":[\"read\"],\"resources\":[\"crm.customer/c-1\"]}}");
            check(ex.status() == 200 && ex.body().get("token") instanceof String && List.of("support-bot", "refund-helper").equals(ex.body().get("chain")), "exchange needs no key: holding the parent token is the authority: " + ex);
            Answer exBad = post(u, "/v1/token", null, "{\"subject_token\":\"junk\",\"actor\":\"refund-helper\"}");
            check(exBad.status() == 400 && !exBad.code().equals("unauthorized") && exBad.body().get("token") == null, "an exchange with a bad parent token is the engine's error: " + exBad);
            Answer idOk = post(u, "/v1/token", null, "{\"id_token\":\"" + ids.get("alice") + "\",\"user\":\"dave\",\"agent\":\"support-bot\",\"cap\":" + FULL + "}");
            check(idOk.status() == 200 && "alice".equals(idOk.body().get("user")), "with an ID token the identity comes from the ID token alone ('user' in the body is dropped): " + idOk);
            for (String kind : List.of("expired", "wrong_audience", "wrong_issuer", "forged")) {
                Answer x = post(u, "/v1/token", null, "{\"id_token\":\"" + ids.get(kind) + "\",\"user\":\"alice\",\"agent\":\"support-bot\",\"cap\":" + FULL + "}");
                check(x.status() == 400 && x.code().equals("id_token_invalid") && x.body().get("token") == null, "a " + kind + " ID token issues nothing: " + x);
            }
            Answer idNull = post(u, "/v1/token", null, "{\"id_token\":null,\"user\":\"alice\",\"agent\":\"support-bot\",\"cap\":" + FULL + "}");
            check(idNull.status() == 400 && idNull.body().get("token") == null, "\"id_token\": null does not fall back to the named user: " + idNull);

            // a deny is a normal answer; an engine error is 400
            String read = "{\"token\":\"" + token + "\",\"action\":\"%s\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"c-1\"}}";
            Answer allow = post(u, "/v1/authorize", P, String.format(read, "read")), deny = post(u, "/v1/authorize", P, String.format(read, "delete"));
            check(allow.status() == 200 && "allow".equals(allow.body().get("effect")), "allow is 200: " + allow);
            check(deny.status() == 200 && "deny".equals(deny.body().get("effect")) && "capability_action".equals(deny.body().get("reason")), "deny is 200 with effect deny: " + deny);
            Answer nonAscii = post(u, "/v1/authorize", P, "{\"token\":\"" + token + "\",\"action\":\"read\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"c-é ✓\"},\"dry_run\":true}");
            check(nonAscii.status() == 200 && nonAscii.body().get("effect") != null, "non-ASCII survives the round trip: " + nonAscii);

            // the body limit: 8 MiB is read, one byte more is refused unread
            byte[] big = new byte[Server.MAX_BODY];
            java.util.Arrays.fill(big, (byte) ' ');
            big[0] = '{';
            big[big.length - 1] = '}';
            Answer atLimit = http(u, "POST", "/v1/authorize", P, big);
            check(atLimit.status() == 400 && String.valueOf(err(atLimit.body()).get("message")).contains("action"), "a body of exactly MAX_BODY bytes reaches the engine: " + atLimit);
            for (String length : new String[] {String.valueOf(Server.MAX_BODY + 1), "99999999999"}) {
                String ans = raw(server, "POST /v1/authorize HTTP/1.1\r\nHost: x\r\nAuthorization: " + P + "\r\nContent-Length: " + length + "\r\n\r\n");
                check(ans.startsWith("HTTP/1.1 400") && ans.contains("request body is too large") && ans.contains("invalid_input"), "Content-Length " + length + " is refused without reading the body: " + ans);
            }
            // a peer that stops sending cannot hold a connection (and a pool thread) for ever
            int limit = Integer.getInteger("sun.net.httpserver.maxReqTime", -1);
            check(limit > 0 && limit <= Server.MAX_REQUEST_SECONDS, "the daemon bounds the time a request may take to arrive: " + limit + " s");
            if (limit <= 10) {
                long t0 = System.nanoTime();
                String refused = raw(server, "POST /v1/authorize HTTP/1.1\r\nHost: x\r\nAuthorization: " + P + "\r\nContent-Length: 99999999\r\n\r\n", true, (limit + 8) * 1000);
                check(refused != null && refused.startsWith("HTTP/1.1 400"), "a refused body: the connection is closed within maxReqTime though the peer never hangs up: " + refused);
                String stalled = raw(server, "POST /v1/authorize HTTP/1.1\r\nHost: x\r\nAuthorization: " + P + "\r\nContent-Length: 100\r\n\r\n{\"token\":", true, (limit + 8) * 1000);
                check(stalled != null && !stalled.contains(" 200 "), "a body that never arrives: the connection is closed, nothing is decided: " + stalled);
                String halfHeaders = raw(server, "GET /v1/info HTTP/1.1\r\nHost: x\r\nAuthori", true, (limit + 8) * 1000);
                check(halfHeaders != null && !halfHeaders.contains(" 200 "), "headers that never end: the connection is closed: " + halfHeaders);
                check(http(u, "GET", "/healthz", null, null).status() == 200 && System.nanoTime() - t0 < TimeUnit.SECONDS.toNanos(3L * (limit + 8)), "and the daemon still answers");
            } else {
                System.out.println("java daemon: stalled-peer checks SKIPPED (run with -Dsun.net.httpserver.maxReqTime=5 or less; run_conformance.sh does)");
            }
            String chunked = raw(server, "POST /v1/authorize HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: " + P + "\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n");
            check(chunked.startsWith("HTTP/1.1 400") && chunked.contains("'action' is required"), "a chunked body is read (and bounded): " + chunked);
            String slashes = raw(server, "GET //v1/info HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: " + P + "\r\n\r\n");
            check(slashes.startsWith("HTTP/1.1 200") && slashes.contains("Server: smartdelegate"), "leading slashes collapse, as in the reference: " + slashes);

            // audit tail takes n from the query
            Answer tail1 = http(u, "GET", "/v1/admin/audit/tail?n=1", A, null), tailBad = http(u, "GET", "/v1/admin/audit/tail?n=abc", A, null),
                    tailHuge = http(u, "GET", "/v1/admin/audit/tail?x=1&n=99999999999999999999", A, null);
            check(tail1.status() == 200 && ((List<Object>) tail1.body().get("records")).size() == 1, "audit tail ?n=1: " + tail1);
            check(tailBad.status() == 200 && ((List<Object>) tailBad.body().get("records")).size() > 1, "audit tail with n that is not a number uses 20");
            check(tailHuge.status() == 200 && ((List<Object>) tailHuge.body().get("records")).size() > 1, "audit tail with a huge n returns what there is");
            Answer v = http(u, "GET", "/v1/admin/audit/verify", A, null);
            check(v.status() == 200 && Boolean.TRUE.equals(v.body().get("ok")), "the audit chain is intact after all of that: " + v);

            // start-up refusals
            for (String[] keys : new String[][] {{"short", PEP}, {ADMIN, "short"}, {"", ""}, {null, PEP}}) {
                try {
                    Server.listen(engine, "127.0.0.1:0", keys[0], keys[1]).close();
                    check(false, "keys shorter than 16 characters must be refused");
                } catch (EngineException e) {
                    check(e.code().equals("invalid_config") && e.detail().startsWith("serve needs admin_key and pep_key"), "short keys are refused: " + e.getMessage());
                }
            }
            for (String listen : new String[] {"127.0.0.1:port", "127.0.0.1:", "127.0.0.1:70000", "127.0.0.1:-1", "nonsense"}) {
                try {
                    Server.listen(engine, listen, ADMIN, PEP).close();
                    check(false, "listen address " + listen + " must be refused");
                } catch (EngineException e) {
                    check(e.code().equals("invalid_config"), "listen address " + listen + ": " + e.getMessage());
                }
            }
            try {
                Server.listen(engine, "127.0.0.1:" + server.port(), ADMIN, PEP).close();
                check(false, "a port in use must be refused");
            } catch (EngineException e) {
                check(e.code().equals("daemon_io"), "a port in use: " + e.getMessage());
            }
            check(Server.listenAddress(":0").getAddress().getHostAddress().equals("127.0.0.1"), "an empty host is loopback");
        } finally {
            Conformance.rm(state);
        }
        passed("java daemon: keys, status codes, body limit, error bodies");
    }

    // ---- 3. concurrency ----------------------------------------------------------

    /** A request that spends 5.00 of the token's budget (and is not rate-limited by a policy). */
    static Map<String, Object> spend(String token, String id) {
        return Json.parseObject("{\"token\":\"" + token + "\",\"action\":\"read\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"" + id + "\"},\"context\":{\"spend\":{\"currency\":\"EUR\",\"amount\":500}}}");
    }

    /** A small refund: the conformance bundle limits these to 3 in 60 seconds (policy refund-small, per engine). */
    static Map<String, Object> refund(String token, String id) {
        return Json.parseObject("{\"token\":\"" + token + "\",\"action\":\"create\",\"resource\":{\"path\":\"billing.refund\",\"id\":\"" + id + "\"},\"context\":{\"spend\":{\"currency\":\"EUR\",\"amount\":1}}}");
    }

    /** Run {@code threads} workers, each calling {@code work(thread, round)} {@code rounds} times, all released at once. Returns the results. */
    static List<Map<String, Object>> hammer(int threads, int rounds, java.util.function.BiFunction<Integer, Integer, Map<String, Object>> work) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);
        List<Future<List<Map<String, Object>>>> futures = new ArrayList<>();
        try {
            for (int t = 0; t < threads; t++) {
                final int thread = t;
                futures.add(pool.submit(() -> {
                    List<Map<String, Object>> out = new ArrayList<>();
                    go.await();
                    for (int r = 0; r < rounds; r++) out.add(work.apply(thread, r));
                    return out;
                }));
            }
            go.countDown();
            List<Map<String, Object>> all = new ArrayList<>();
            for (Future<List<Map<String, Object>>> f : futures) all.addAll(f.get(120, TimeUnit.SECONDS));
            return all;
        } finally {
            pool.shutdownNow();
        }
    }

    @SuppressWarnings("unchecked")
    static void concurrency(Path root, List<String> cli) throws Exception {
        final int threads = 48, rounds = 5;   // more threads than the daemon's pool
        Path work = Files.createTempDirectory("smartdelegate-java-c-");
        try {
            // (a) one daemon, many clients: 240 requests of 5.00 against a budget of 200.00, mixed with refunds
            // under a rate limit of 3 per minute, and with issuance, exchange and revocation of other tokens
            Path state = work.resolve("daemon-state");
            Map<String, Object> cfg = Conformance.config(root, state);
            try (Engine engine = new Engine(cfg); Server server = Server.listen(engine, "127.0.0.1:0", ADMIN, PEP)) {
                Client admin = new Client(server.url(), PEP, ADMIN);
                String token = (String) admin.call("issue_token", Json.parseObject("{\"user\":\"alice\",\"agent\":\"support-bot\",\"cap\":" + FULL + "}")).get("token");
                String refunds = (String) admin.call("issue_token", Json.parseObject("{\"user\":\"alice\",\"agent\":\"support-bot\",\"cap\":" + FULL + "}")).get("token");
                check(token != null && refunds != null, "two tokens with a budget of 20000 each");
                AtomicInteger transport = new AtomicInteger();
                java.util.Queue<Map<String, Object>> limited = new java.util.concurrent.ConcurrentLinkedQueue<>();
                Client[] clients = new Client[threads];   // a connection pool each, like separate enforcement points
                for (int i = 0; i < threads; i++) clients[i] = new Client(server.url(), PEP, ADMIN);
                List<Map<String, Object>> results = hammer(threads, rounds, (t, r) -> {
                    Client c = clients[t];
                    try {
                        if (t % 4 == 3) {
                            // noise that also writes state and audit records
                            Map<String, Object> other = c.call("issue_token", Json.parseObject("{\"user\":\"alice\",\"agent\":\"support-bot\",\"cap\":{\"actions\":[\"read\"],\"resources\":[\"crm.customer/*\"]}}"));
                            c.call("authorize", Json.parseObject("{\"token\":\"" + other.get("token") + "\",\"action\":\"read\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"c-1\"}}"));
                            c.call("exchange_token", Json.parseObject("{\"subject_token\":\"" + other.get("token") + "\",\"actor\":\"refund-helper\",\"ttl\":300}"));
                            c.call("revoke", Json.parseObject("{\"token\":\"" + other.get("token") + "\",\"by\":\"test\"}"));
                        }
                        if (t % 4 == 0) limited.add(c.call("authorize", refund(refunds, "r-" + t + "-" + r)));
                        return c.call("authorize", spend(token, "c-" + t + "-" + r));
                    } catch (RuntimeException e) {
                        transport.incrementAndGet();
                        return new LinkedHashMap<>(Map.of("ok", false, "thrown", String.valueOf(e)));
                    }
                });
                long allowed = results.stream().filter(x -> "allow".equals(x.get("effect"))).count();
                long overBudget = results.stream().filter(x -> "deny".equals(x.get("effect")) && "budget_exceeded".equals(x.get("reason"))).count();
                check(transport.get() == 0 && results.stream().allMatch(x -> Boolean.TRUE.equals(x.get("ok"))), "every one of " + results.size() + " concurrent requests is answered: " + results.stream().filter(x -> !Boolean.TRUE.equals(x.get("ok"))).findFirst().orElse(null));
                check(results.size() == threads * rounds && allowed == 40 && overBudget == results.size() - 40, "exactly 40 requests of 500 fit a budget of 20000; allowed " + allowed + ", budget_exceeded " + overBudget + " of " + results.size());
                long refunded = limited.stream().filter(x -> "allow".equals(x.get("effect"))).count(), rateLimited = limited.stream().filter(x -> "rate_limited".equals(x.get("reason"))).count();
                check(limited.size() == threads / 4 * rounds && refunded == 3 && rateLimited == limited.size() - 3, "a rate limit of 3 per minute lets exactly 3 through; allowed " + refunded + ", rate_limited " + rateLimited + " of " + limited.size());
                Map<String, Object> more = admin.call("authorize", spend(token, "c-late"));
                check("budget_exceeded".equals(more.get("reason")), "the budget stays spent: " + Json.write(more));
                Map<String, Object> v = admin.call("audit_verify", new LinkedHashMap<>());
                long lines = Files.readAllLines(state.resolve("audit.jsonl")).stream().filter(l -> !l.isBlank()).count();
                check(Boolean.TRUE.equals(v.get("ok")) && Long.valueOf(lines).equals(v.get("records")) && lines >= results.size() + limited.size(), "the audit chain is valid after the run: " + Json.write(v) + ", " + lines + " lines");
                long spent = 0;
                for (String line : Files.readAllLines(state.resolve("audit.jsonl"))) {
                    Map<String, Object> rec = Json.parseObject(line);
                    if ("decision".equals(rec.get("event")) && "allow".equals(rec.get("effect")) && rec.get("spend") instanceof Map<?, ?> sp
                            && String.valueOf(rec.get("resource")).startsWith("crm.customer/c-")) spent += (Long) sp.get("amount");
                }
                check(spent == 20000, "the audit log accounts for exactly the budget: " + spent);
                // ... and the reference agrees, record for record
                Path rc = work.resolve("daemon.json");
                Files.writeString(rc, Json.write(cfg));
                Map<String, Object> rv = Json.parseObject(Conformance.run(Conformance.with(cli, "audit", "verify", "--config", rc.toString())));
                check(Boolean.TRUE.equals(rv.get("ok")) && v.get("records").equals(rv.get("records")) && v.get("head").equals(rv.get("head")), "the reference verifies the same chain: " + Json.write(rv));
            }

            // (b) two engines in this JVM on one state directory, called directly from many threads
            Path shared = work.resolve("shared-state");
            try (Engine one = new Engine(Conformance.config(root, shared)); Engine two = new Engine(Conformance.config(root, shared))) {
                String token = (String) one.call("issue_token", Json.parseObject("{\"user\":\"alice\",\"agent\":\"support-bot\",\"cap\":" + FULL + "}")).get("token");
                List<Map<String, Object>> results = hammer(16, 8, (t, r) -> (t % 2 == 0 ? one : two).call("authorize", spend(token, "s-" + t + "-" + r)));
                long allowed = results.stream().filter(x -> "allow".equals(x.get("effect"))).count();
                check(results.stream().allMatch(x -> Boolean.TRUE.equals(x.get("ok"))) && allowed == 40 && results.size() == 128, "two engines on one state directory: allowed " + allowed + " of " + results.size());
                Map<String, Object> v1 = one.call("audit_verify", new LinkedHashMap<>()), v2 = two.call("audit_verify", new LinkedHashMap<>());
                check(Boolean.TRUE.equals(v1.get("ok")) && v1.equals(v2) && Long.valueOf(129).equals(v1.get("records")), "one audit chain, 1 issuance + 128 decisions: " + Json.write(v1));
            }
        } finally {
            Conformance.rm(work);
        }
        passed("java daemon: concurrent requests (budget never exceeded, audit chain valid)");
    }

    // ---- 4. command line -----------------------------------------------------------

    record Ran(int code, String out, String err) {
        Map<String, Object> json() {
            try {
                return Json.parseObject(out);
            } catch (RuntimeException e) {
                throw new AssertionError("not JSON on stdout: [" + out + "] stderr [" + err + "]");
            }
        }
    }

    /** The command line in this JVM: exit code, stdout, stderr. */
    static Ran cli(Map<String, String> env, String stdin, String... argv) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(), err = new ByteArrayOutputStream();
        int code = Cli.run(argv, new ByteArrayInputStream((stdin == null ? "" : stdin).getBytes(StandardCharsets.UTF_8)),
                new PrintStream(out, true, StandardCharsets.UTF_8), new PrintStream(err, true, StandardCharsets.UTF_8), env);
        return new Ran(code, out.toString(StandardCharsets.UTF_8).strip(), err.toString(StandardCharsets.UTF_8).strip());
    }

    static Ran cli(String... argv) {
        return cli(Map.of(), null, argv);
    }

    static String[] with(String config, String... argv) {
        List<String> all = new ArrayList<>(List.of(argv));
        all.add("--config");
        all.add(config);
        return all.toArray(String[]::new);
    }

    /** A process with a timeout: exit code, stdout, stderr. */
    static Ran exec(List<String> cmd, Map<String, String> env, Path scratch) throws Exception {
        Path out = Files.createTempFile(scratch, "out", ".txt"), err = Files.createTempFile(scratch, "err", ".txt");
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectOutput(out.toFile()).redirectError(err.toFile()).redirectInput(ProcessBuilder.Redirect.from(new java.io.File(System.getProperty("os.name").startsWith("Windows") ? "NUL" : "/dev/null")));
        if (env != null) pb.environment().putAll(env);
        Process p = pb.start();
        if (!p.waitFor(120, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new AssertionError("timed out after 120 s: " + cmd);
        }
        return new Ran(p.exitValue(), Files.readString(out).strip(), Files.readString(err).strip());
    }

    @SuppressWarnings("unchecked")
    static void commandLine(Path root, List<String> ref) throws Exception {
        Path work = Files.createTempDirectory("smartdelegate-java-cli-");
        try {
            check(cli("--version").out().equals("smartdelegate 0.3.0 (java)") && cli("-V").code() == 0 && cli("version").out().equals("smartdelegate 0.3.0 (java)"), "--version");
            Ran help = cli("--help"), none = cli(), unknown = cli("frobnicate"), midHelp = cli("token", "issue", "--help");
            check(help.code() == 0 && help.out().contains("serve [--listen") && none.code() == 0 && none.out().equals(help.out()) && midHelp.out().equals(help.out()), "--help and no arguments print the help");
            check(unknown.code() == 1 && unknown.out().isEmpty() && unknown.err().contains("USAGE"), "an unknown command prints the help on stderr and exits 1");
            for (String elsewhere : List.of("http-proxy", "mcp-proxy", "bridge", "init", "bench", "--demo")) {
                Ran r = cli(elsewhere);
                check(r.code() == 1 && r.err().contains("not part of the Java port"), elsewhere + " says where to find it: " + r);
            }

            // configuration: relative paths are relative to the config file, not to the working directory
            Path conf = Files.createDirectories(work.resolve("conf"));
            Conformance.copyBundle(root, conf.resolve("bundle"));
            Files.copy(root.resolve("spec/conformance/oidc/jwks.json"), conf.resolve("jwks.json"));
            Path cfgFile = conf.resolve("smartdelegate.json");
            Files.writeString(cfgFile, "﻿{\"bundle_dir\":\"bundle\",\"state_dir\":\"state\",\"allow_test_clock\":true,\"max_depth\":3,"
                    + "\"idp\":{\"issuer\":\"https://idp.example.test\",\"audience\":\"smartdelegate-demo\",\"jwks_file\":\"jwks.json\"}}");
            String cfg = cfgFile.toString();
            Ran info = cli(with(cfg, "info"));
            check(info.code() == 0 && "java".equals(info.json().get("implementation")) && "https://idp.example.test".equals(info.json().get("oidc")) && info.out().startsWith("{\n  \"version\": \"0.3.0\","),
                    "info with a config file (BOM, relative bundle_dir, state_dir and jwks_file): " + info);
            check(Files.exists(conf.resolve("state").resolve("signing_key.pub.b64")), "state_dir is relative to the config file");
            Map<String, Object> refInfo = Json.parseObject(Conformance.run(Conformance.with(ref, "info", "--config", cfg)));
            for (String k : List.of("version", "policy_version", "policies", "resources", "roles", "mode", "issuer", "key_id", "public_key", "can_issue", "oidc", "bundle_signed_by"))
                check(java.util.Objects.equals(refInfo.get(k), info.json().get(k)), "info." + k + " is what the reference reports for the same config file: " + refInfo.get(k) + " / " + info.json().get(k));
            Path link = work.resolve("link.json");
            try {
                Files.createSymbolicLink(link, cfgFile);
                check(cli(with(link.toString(), "info")).code() == 0, "a symlinked config file resolves paths from the real file");
            } catch (IOException | UnsupportedOperationException e) {
                // no symlinks here (Windows without the privilege)
            }
            check(cli(Map.of("SMARTDELEGATE_CONFIG", cfg), null, "info").code() == 0, "SMARTDELEGATE_CONFIG names the config file");
            Ran flagWins = cli(Map.of("SMARTDELEGATE_CONFIG", work.resolve("missing.json").toString()), null, with(cfg, "info"));
            check(flagWins.code() == 0, "--config wins over SMARTDELEGATE_CONFIG: " + flagWins);
            Ran missing = cli(with(work.resolve("missing.json").toString(), "info"));
            check(missing.code() == 1 && missing.out().isEmpty() && missing.err().startsWith("smartdelegate: "), "a missing config file: " + missing);
            Files.writeString(work.resolve("list.json"), "[]");
            check(cli(with(work.resolve("list.json").toString(), "info")).code() == 1, "a config file that is not an object");
            Ran noBundle = cli("info");
            check(noBundle.code() == 1 && noBundle.err().startsWith("smartdelegate: no bundle"), "no bundle: " + noBundle);
            Ran badBundle = cli("info", "--bundle", work.resolve("nowhere").toString());
            check(badBundle.code() == 1 && badBundle.err().startsWith("smartdelegate: bundle_io: "), "a bundle that does not load: " + badBundle);
            Ran over = cli(with(cfg, "info", "--state", work.resolve("other-state").toString(), "--bundle", root.resolve("spec/conformance/bundle").toString(), "--shadow"));
            check(over.code() == 0 && "shadow".equals(over.json().get("mode")) && Files.exists(work.resolve("other-state").resolve("signing_key.pub.b64")), "--bundle, --state and --shadow override the file: " + over);
            Ran check = cli(with(cfg, "policy", "check"));
            check(check.code() == 0 && check.out().equals("bundle loads: 21 policies, version " + info.json().get("policy_version")), "policy check: " + check);
            Ran ptest = cli(with(cfg, "policy", "test"));
            String refTest = Conformance.run(Conformance.with(ref, "policy", "test", "--config", cfg));
            check(ptest.code() == 0 && ptest.out().equals(refTest) && ptest.out().endsWith(" tests, 0 failed") && !ptest.out().startsWith("0 tests"), "policy test prints what the reference prints: " + ptest);

            // tokens
            Path cap = work.resolve("cap.json");
            Files.writeString(cap, FULL);
            Ran issued = cli(with(cfg, "token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "@" + cap, "--task", "ticket-7", "--ttl", "600", "--raw"));
            check(issued.code() == 0 && issued.out().split("\\.").length == 3, "token issue --raw prints the token: " + issued);
            String token = issued.out();
            Ran inspected = cli(with(cfg, "token", "inspect", "--token", token));
            Map<String, Object> claims = (Map<String, Object>) inspected.json().get("claims");
            check(inspected.code() == 0 && Boolean.TRUE.equals(inspected.json().get("valid")) && "ticket-7".equals(claims.get("task")) && (Long) claims.get("exp") - (Long) claims.get("iat") == 600, "token inspect, --task and --ttl: " + inspected);
            check(cli(with(cfg, "token", "issue", "--user", "alice", "--agent", "support-bot")).code() == 1, "--cap or --role is required");
            check(cli(with(cfg, "token", "issue", "--user", "alice", "--cap", FULL)).code() == 1, "--agent is required");
            check(cli(with(cfg, "token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "{")).code() == 1, "--cap must be JSON");
            check(cli(with(cfg, "token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", FULL, "--ttl", "soon")).code() == 1, "--ttl must be a number");
            Ran noUser = cli(with(cfg, "token", "issue", "--user", "nobody", "--agent", "support-bot", "--cap", FULL, "--raw"));
            check(noUser.code() == 1 && Boolean.FALSE.equals(noUser.json().get("ok")), "a refused issuance exits 1 and prints the error, also with --raw: " + noUser);
            Ran role = cli(with(cfg, "token", "issue", "--user", "dave", "--agent", "support-bot", "--role", "support-agent", "--groups", "support,,"));
            check(role.code() == 0 && "support-agent".equals(role.json().get("role")), "--role with --groups: " + role);
            Ran noRole = cli(with(cfg, "token", "issue", "--user", "dave", "--agent", "support-bot", "--role", "support-agent"));
            check(noRole.code() == 1 && "role_not_held".equals(err(noRole.json()).get("code")), "--role without the live membership: " + noRole);
            Map<String, Object> ids = Json.parseObject(Files.readString(root.resolve("spec/conformance/oidc/id_tokens.json")));
            Ran byId = cli(with(cfg, "token", "issue", "--agent", "support-bot", "--cap", FULL, "--id-token", (String) ids.get("alice")));
            check(byId.code() == 0 && "alice".equals(byId.json().get("user")), "--id-token: " + byId);
            Ran child = cli(with(cfg, "token", "exchange", "--token", token, "--actor", "refund-helper", "--cap", "{\"actions\":[\"read\"],\"resources\":[\"crm.customer/c-1\"],\"deny_labels\":[\"pii\"]}", "--ttl", "300", "--raw"));
            check(child.code() == 0 && child.out().split("\\.").length == 3, "token exchange --raw: " + child);

            // decisions and exit codes: 0 allow, 2 deny, 1 error
            Ran allow = cli(with(cfg, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-1"));
            check(allow.code() == 0 && "allow".equals(allow.json().get("effect")), "allow exits 0: " + allow);
            Ran deny = cli(with(cfg, "authorize", "--token", token, "--action", "delete", "--resource", "crm.customer/c-1"));
            check(deny.code() == 2 && "deny".equals(deny.json().get("effect")) && "capability_action".equals(deny.json().get("reason")), "deny exits 2: " + deny);
            Ran junk = cli(with(cfg, "authorize", "--token", "junk", "--action", "read", "--resource", "crm.customer/c-1"));
            check(junk.code() == 2 && "token_invalid".equals(junk.json().get("reason")), "a bad token is a deny: " + junk);
            Ran error = cli(with(cfg, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-1", "--context", "{\"iam\":1}"));
            check(error.code() == 1 && Boolean.FALSE.equals(error.json().get("ok")), "an engine error exits 1: " + error);
            check(cli(with(cfg, "authorize", "--token", token, "--resource", "crm.customer/c-1")).code() == 1, "--action is required");
            Ran shadow = cli(with(cfg, "authorize", "--token", token, "--action", "delete", "--resource", "crm.customer/c-1", "--shadow"));
            check(shadow.code() == 0 && "shadow_allow".equals(shadow.json().get("reason")), "--shadow logs the would-be denial and allows: " + shadow);
            Ran dry = cli(with(cfg, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer", "--dry-run", "--strict"));
            check(dry.code() == 0 || dry.code() == 2, "--dry-run and --strict are passed on: " + dry);
            Ran filtered = cli(with(cfg, "authorize", "--token", child.out(), "--action", "read", "--resource", "crm.customer/c-1", "--data", "{\"id\":\"c-1\",\"region\":\"EU\",\"email\":\"ada@example.com\",\"ssn\":\"123-45-6789\"}"));
            check(filtered.code() == 0 && Json.parse("{\"id\":\"c-1\",\"region\":\"EU\"}").equals(filtered.json().get("data")), "--data filters the record: " + filtered);
            Ran explained = cli(with(cfg, "explain", "--token", token, "--action", "read", "--resource", "crm.customer/c-1"));
            check(explained.code() == 0 && explained.json().get("explain") != null, "explain: " + explained);
            Ran attrs = cli(with(cfg, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-9", "--attrs", "{\"region\":\"EU\"}", "--context", "{\"note\":\"é ✓\"}"));
            check(attrs.code() == 0, "--attrs and --context: " + attrs);

            // approval
            String spend = "{\"spend\":{\"currency\":\"EUR\",\"amount\":15000}}";
            Ran held = cli(with(cfg, "authorize", "--token", token, "--action", "create", "--resource", "billing.refund/r-1", "--context", spend));
            Map<String, Object> approval = held.json().get("approval") instanceof Map ? (Map<String, Object>) held.json().get("approval") : Map.of();
            String approvalId = held.json().get("approval_id") instanceof String s ? s : (String) approval.get("id");
            check(held.code() == 2 && approvalId != null, "a large refund is held (exit 2): " + held);
            Ran pending = cli(with(cfg, "approvals"));
            check(pending.code() == 0 && ((Map<String, Object>) pending.json().get("pending")).containsKey(approvalId), "approvals lists it: " + pending);
            check(cli(with(cfg, "approve", approvalId)).code() == 1, "approve needs --by");
            check(cli(with(cfg, "approve", approvalId, "--by", "bob")).code() == 0, "approve <id> --by");
            check(cli(with(cfg, "authorize", "--token", token, "--action", "create", "--resource", "billing.refund/r-1", "--context", spend)).code() == 0, "the approved refund is allowed");

            // call: any operation, input inline, from a file or from standard input
            Path in = work.resolve("in.json");
            Files.writeString(in, "{\"token\":\"" + token + "\"}");
            check(cli(with(cfg, "call", "inspect_token", "--input", "@" + in)).code() == 0, "call --input @file");
            check(cli(Map.of(), "{\"token\":\"" + token + "\"}", with(cfg, "call", "inspect_token", "--input", "-")).code() == 0, "call --input -");
            check(cli(with(cfg, "call", "info")).code() == 0 && cli(with(cfg, "call", "info", "--input", "{}")).code() == 0, "call without input");
            Ran noOp = cli(with(cfg, "call", "frobnicate"));
            check(noOp.code() == 1 && "unknown_op".equals(err(noOp.json()).get("code")), "call with an unknown operation: " + noOp);
            Ran notObject = cli(with(cfg, "call", "authorize", "--input", "[]"));
            check(notObject.code() == 1 && "invalid_input".equals(err(notObject.json()).get("code")), "call with input that is not an object: " + notObject);
            check(cli(Map.of(), "{", with(cfg, "call", "info", "--input", "-")).code() == 1, "call with input that is not JSON");
            Ran callDeny = cli(with(cfg, "call", "authorize", "--input", "{\"token\":\"" + token + "\",\"action\":\"delete\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"c-1\"}}"));
            check(callDeny.code() == 2, "call authorize exits 2 on deny: " + callDeny);

            // revocation
            Ran revoked = cli(with(cfg, "token", "revoke", "--token", child.out()));
            check(revoked.code() == 0, "token revoke --token: " + revoked);
            Ran afterRevoke = cli(with(cfg, "authorize", "--token", child.out(), "--action", "read", "--resource", "crm.customer/c-1"));
            check(afterRevoke.code() == 2 && "token_revoked".equals(afterRevoke.json().get("reason")), "a revoked token is denied: " + afterRevoke);
            Ran byIdRevoke = cli(with(cfg, "token", "revoke", "--id", (String) role.json().get("token_id")));
            check(byIdRevoke.code() == 0 && cli(with(cfg, "authorize", "--token", (String) role.json().get("token"), "--action", "read", "--resource", "crm.customer/c-1")).code() == 2, "token revoke --id: " + byIdRevoke);
            check(cli(with(cfg, "token", "revoke")).code() == 1, "token revoke needs --id, --token or --user");

            // tokens across implementations, through both command lines
            Map<String, Object> verifier = Conformance.config(root, work.resolve("ref-verifier"));
            verifier.put("verify_only", true);
            verifier.put("trusted_keys", List.of(info.json().get("public_key")));
            Path vc = work.resolve("ref-verifier.json");
            Files.writeString(vc, Json.write(verifier));
            Map<String, Object> rd = Json.parseObject(Conformance.run(Conformance.with(ref, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-1", "--config", vc.toString())));
            check("allow".equals(rd.get("effect")), "a token issued by the java command line is accepted by the reference: " + Json.write(rd));
            Path refCfg = work.resolve("ref.json");
            Files.writeString(refCfg, Json.write(Conformance.config(root, work.resolve("ref-state"))));
            String refToken = Conformance.run(Conformance.with(ref, "token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "@" + cap, "--raw", "--config", refCfg.toString()));
            Map<String, Object> jv = Conformance.config(root, work.resolve("java-verifier"));
            jv.put("verify_only", true);
            jv.put("trusted_keys", List.of(Files.readString(work.resolve("ref-state").resolve("signing_key.pub.b64")).strip()));
            Path jvc = work.resolve("java-verifier.json");
            Files.writeString(jvc, Json.write(jv));
            Ran jd = cli(with(jvc.toString(), "authorize", "--token", refToken, "--action", "read", "--resource", "crm.customer/c-1"));
            check(jd.code() == 0 && "allow".equals(jd.json().get("effect")), "a token issued by the reference is accepted by the java command line: " + jd);
            Ran foreign = cli(with(cfg, "authorize", "--token", refToken, "--action", "read", "--resource", "crm.customer/c-1"));
            check(foreign.code() == 2 && "deny".equals(foreign.json().get("effect")), "and denied where its key is not trusted: " + foreign);
            Ran verifyOnlyIssue = cli(with(jvc.toString(), "token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", FULL));
            check(verifyOnlyIssue.code() == 1, "a verify-only engine issues nothing: " + verifyOnlyIssue);

            // offboarding
            Ran userRevoked = cli(with(cfg, "token", "revoke", "--user", "alice"));
            check(userRevoked.code() == 0 && "alice".equals(userRevoked.json().get("revoked_user")), "token revoke --user: " + userRevoked);
            check(cli(with(cfg, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-1")).code() == 2, "every token of the user is dead");

            // audit, and the same log in the reference's eyes
            Ran verified = cli(with(cfg, "audit", "verify"));
            check(verified.code() == 0 && (Long) verified.json().get("records") > 20, "audit verify: " + verified);
            Map<String, Object> rv = Json.parseObject(Conformance.run(Conformance.with(ref, "audit", "verify", "--config", cfg)));
            check(Boolean.TRUE.equals(rv.get("ok")) && verified.json().get("records").equals(rv.get("records")) && verified.json().get("head").equals(rv.get("head")),
                    "the reference verifies the log the java command line wrote, same count and head: " + Json.write(rv));
            Ran tail = cli(with(cfg, "audit", "tail", "-n", "3"));
            String refTail = Conformance.run(Conformance.with(ref, "audit", "tail", "-n", "3", "--config", cfg));
            check(tail.code() == 0 && tail.out().split("\n").length == 3 && tail.out().equals(refTail), "audit tail -n 3 prints the lines the reference prints: " + tail);
            check(cli(with(cfg, "audit", "tail")).out().split("\n").length == 20 && cli(with(cfg, "audit", "tail", "-n", "x")).code() == 1, "audit tail defaults to 20; -n must be a number");
            // the reference wrote two more records (its own verify did not; its tail did not): the chain continues across implementations
            Conformance.run(Conformance.with(ref, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-1", "--config", cfg));
            Ran continued = cli(with(cfg, "audit", "verify"));
            check(continued.code() == 0 && (Long) continued.json().get("records") == (Long) verified.json().get("records") + 1, "a record appended by the reference continues the chain (used one after the other): " + continued);
            Path log = conf.resolve("state").resolve("audit.jsonl");
            Files.writeString(log, Files.readString(log).replaceFirst("\"reason\":\"capability_action\"", "\"reason\":\"policy_permit\""));
            Ran tampered = cli(with(cfg, "audit", "verify"));
            check(tampered.code() == 1 && tampered.err().contains("audit_broken") && tampered.out().isEmpty(), "a tampered log is refused, exit 1: " + tampered);

            // bundle signing through both command lines, both directions
            Path b = work.resolve("signed-bundle");
            Conformance.copyBundle(root, b);
            Ran keygen = cli("bundle", "keygen", work.resolve("jk").toString());
            String pub = Files.readString(work.resolve("jk.pub"));
            check(keygen.code() == 0 && keygen.out().contains("\"bundle_public_key\": \"" + pub + "\"") && java.util.Base64.getDecoder().decode(pub).length == 32, "bundle keygen: " + keygen);
            try {
                check(java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(work.resolve("jk.key"))).equals("rw-------"), "the private key file is owner-only");
                Files.setPosixFilePermissions(work.resolve("jk.key"), java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
                check(cli("bundle", "keygen", work.resolve("jk").toString()).code() == 0
                        && java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(work.resolve("jk.key"))).equals("rw-------"), "also when the file existed with a wider mode");
                pub = Files.readString(work.resolve("jk.pub"));
            } catch (UnsupportedOperationException e) {
                // not a POSIX file system
            }
            check(cli("bundle", "keygen").code() == 1 && cli("bundle", "sign", "--bundle", b.toString()).code() == 1, "keygen needs a prefix, sign needs --key");
            Ran signed = cli("bundle", "sign", "--key", work.resolve("jk.key").toString(), "--bundle", b.toString());
            Map<String, Object> sig = Json.parseObject(Files.readString(b.resolve("bundle.sig.json")));
            check(signed.code() == 0 && signed.out().equals("signed bundle version " + sig.get("version") + " with key " + sig.get("key_id")), "bundle sign: " + signed);
            Path sc = work.resolve("signed.json");
            Files.writeString(sc, Json.write(Map.of("bundle_dir", b.toString(), "bundle_public_key", pub)));
            Map<String, Object> refSigned = Json.parseObject(Conformance.run(Conformance.with(ref, "info", "--config", sc.toString())));
            check(sig.get("key_id").equals(refSigned.get("bundle_signed_by")), "a bundle signed by the java command line loads in the reference with bundle_public_key: " + Json.write(refSigned));
            check(sig.get("key_id").equals(cli(with(sc.toString(), "info")).json().get("bundle_signed_by")), "and in java");
            Conformance.run(Conformance.with(ref, "bundle", "keygen", work.resolve("rk").toString()));
            String refSignOut = Conformance.run(Conformance.with(ref, "bundle", "sign", "--key", work.resolve("rk.key").toString(), "--bundle", b.toString()));
            Path rsc = work.resolve("ref-signed.json");
            Files.writeString(rsc, Json.write(Map.of("bundle_dir", b.toString(), "bundle_public_key", Files.readString(work.resolve("rk.pub")).strip())));
            Ran javaLoads = cli(with(rsc.toString(), "info"));
            check(javaLoads.code() == 0 && refSignOut.endsWith("with key " + javaLoads.json().get("bundle_signed_by")), "a bundle signed by the reference command line loads in java: " + javaLoads + " / " + refSignOut);
            Ran wrongKey = cli(with(sc.toString(), "info"));
            check(wrongKey.code() == 1 && wrongKey.err().contains("bundle_signature"), "signed by another key than the configured one: refused: " + wrongKey);
            check(cli("bundle", "sign", "--key", work.resolve("rk.key").toString(), "--bundle", b.toString()).out().equals(refSignOut), "java and the reference print the same version and key id for the same key and bundle");
            Files.writeString(b.resolve("entities.json"), Files.readString(b.resolve("entities.json")).replaceFirst("\"region\": \"EU\"", "\"region\": \"US\""));
            Ran changed = cli(with(rsc.toString(), "info"));
            check(changed.code() == 1 && changed.err().contains("bundle_signature") && changed.out().isEmpty(), "a bundle changed after signing does not load: " + changed);
            String refChanged = Conformance.run(Conformance.with(ref, "info", "--config", rsc.toString()));
            check(refChanged.contains("bundle_signature"), "nor in the reference: " + refChanged);
            Files.writeString(work.resolve("bad.key"), "not a key");
            check(cli("bundle", "sign", "--key", work.resolve("bad.key").toString(), "--bundle", b.toString()).code() == 1, "a key file that is not a key");
            check(cli("bundle", "compile", "--bundle", b.toString()).code() == 1, "bundle compile points at the Rust port");

            // serve refuses to start without keys; conformance runs the repository's vectors
            Ran noKeys = cli(with(cfg, "serve", "--listen", "127.0.0.1:0", "--state", work.resolve("serve-state").toString()));
            check(noKeys.code() == 1 && noKeys.err().equals("smartdelegate: serve needs admin_key and pep_key (16+ characters) in the config or SMARTDELEGATE_ADMIN_KEY / SMARTDELEGATE_PEP_KEY"), "serve without keys: " + noKeys);
            Ran badListen = cli(Map.of("SMARTDELEGATE_ADMIN_KEY", ADMIN, "SMARTDELEGATE_PEP_KEY", PEP), null, with(cfg, "serve", "--listen", "127.0.0.1:http", "--state", work.resolve("serve-state").toString()));
            check(badListen.code() == 1 && badListen.err().contains("the port must be a number"), "serve with a bad address: " + badListen);
            Ran conformance = cli("conformance", "--root", root.toString());
            check(conformance.code() == 0 && conformance.out().contains("java policy evaluation (against real Cedar's answers): 95 cases, 0 failed") && conformance.out().endsWith("java conformance: 78 cases, 0 failed"), "conformance --root: " + conformance);
            Ran explicit = cli("conformance", root.resolve("spec/conformance/vectors").toString(), root.resolve("spec/conformance/bundle").toString());
            check(explicit.code() == 0 && explicit.out().endsWith("java conformance: 78 cases, 0 failed"), "conformance <vectors> <bundle>: " + explicit);
            Ran wrongBundle = cli("conformance", root.resolve("spec/conformance/vectors").toString(), root.resolve("examples/company").toString());
            check(wrongBundle.code() == 1, "conformance against another bundle fails: exit " + wrongBundle.code());
            check(cli("conformance", work.toString(), root.resolve("spec/conformance/bundle").toString()).code() == 1, "a directory without vectors is not a pass");
        } finally {
            Conformance.rm(work);
        }
        passed("java command line (commands, config, exit codes, cross-checks with the reference)");
    }

    // ---- 5. the launcher script ----------------------------------------------------

    static void launcher(Path root, String launcher) throws Exception {
        Path work = Files.createTempDirectory("smartdelegate-java-l-");
        Process daemon = null;
        try {
            Map<String, Object> cfg = Conformance.config(root, work.resolve("state"));
            cfg.put("admin_key", ADMIN);
            cfg.put("pep_key", PEP);
            Path cfgFile = work.resolve("smartdelegate.json");
            Files.writeString(cfgFile, Json.write(cfg));
            // JAVA_TOOL_OPTIONS makes a bare JVM print a banner on stderr before anything else
            Map<String, String> env = Map.of("JAVA_TOOL_OPTIONS", "-Dsmartdelegate.test=1");
            Ran version = exec(List.of(launcher, "--version"), env, work);
            check(version.code() == 0 && version.out().equals("smartdelegate 0.3.0 (java)") && version.err().isEmpty(), "the launcher runs the command line and prints nothing else: " + version);

            ProcessBuilder pb = new ProcessBuilder(launcher, "serve", "--config", cfgFile.toString(), "--listen", "127.0.0.1:0").redirectOutput(ProcessBuilder.Redirect.DISCARD);
            pb.environment().putAll(env);
            daemon = pb.start();
            final Process proc = daemon;
            ExecutorService reader = Executors.newSingleThreadExecutor();
            String first;
            try {
                first = reader.submit(() -> new java.io.BufferedReader(new java.io.InputStreamReader(proc.getErrorStream(), StandardCharsets.UTF_8)).readLine()).get(60, TimeUnit.SECONDS);
            } finally {
                reader.shutdownNow();
            }
            Matcher m = Pattern.compile("^smartdelegate daemon listening on (http://127\\.0\\.0\\.1:[0-9]+)$").matcher(first == null ? "" : first);
            check(m.matches(), "the first line `serve` writes to stderr is its URL, also with JAVA_TOOL_OPTIONS set: " + first);
            String url = m.group(1);
            Client iam = new Client(url, PEP, ADMIN);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
            while (http(url, "GET", "/healthz", null, null).status() != 200) check(System.nanoTime() < deadline, "/healthz answers");
            String token = (String) iam.issueToken("alice", "support-bot", Json.parseObject(FULL)).get("token");
            check("allow".equals(iam.authorize(token, "read", "crm.customer", "c-1", null).get("effect")), "the daemon started by the launcher decides");
            check("implementation".length() > 0 && "java".equals(iam.call("info", new LinkedHashMap<>()).get("implementation")), "and it is the java engine");

            // the command line next to the running daemon, on the same state directory (serialised by the lock file)
            String c = cfgFile.toString();
            Ran allow = exec(List.of(launcher, "authorize", "--token", token, "--action", "read", "--resource", "crm.customer/c-1", "--config", c), env, work);
            Ran deny = exec(List.of(launcher, "authorize", "--token", token, "--action", "delete", "--resource", "crm.customer/c-1", "--config", c), env, work);
            Ran error = exec(List.of(launcher, "call", "frobnicate", "--config", c), env, work);
            check(allow.code() == 0 && deny.code() == 2 && error.code() == 1 && allow.err().isEmpty(), "exit codes through the launcher: allow " + allow.code() + ", deny " + deny.code() + ", error " + error.code());
            Ran revoke = exec(List.of(launcher, "token", "revoke", "--token", token, "--config", c), env, work);
            check(revoke.code() == 0 && "token_revoked".equals(iam.authorize(token, "read", "crm.customer", "c-1", null).get("reason")), "a token revoked from the command line is refused by the running daemon");
            check(Boolean.TRUE.equals(iam.call("audit_verify", new LinkedHashMap<>()).get("ok")), "one audit chain, written by the daemon and by the command line");

            daemon.destroy();   // SIGTERM
            check(daemon.waitFor(20, TimeUnit.SECONDS), "the daemon stops on SIGTERM");
            try {
                iam.call("info", new LinkedHashMap<>());
                check(false, "the port is closed after the daemon stopped");
            } catch (SmartDelegateException e) {
                check(e.code().equals("daemon_unreachable"), "the port is closed: " + e.code());
            }
            Ran after = exec(List.of(launcher, "audit", "verify", "--config", c), env, work);
            check(after.code() == 0, "the state directory is intact after the stop: " + after);
        } finally {
            if (daemon != null && daemon.isAlive()) {
                daemon.destroyForcibly();
                daemon.waitFor(20, TimeUnit.SECONDS);
            }
            Conformance.rm(work);
        }
        passed("java launcher (bin/smartdelegate-java: serve, exit codes, SIGTERM)");
    }

    // ---- 5b. OIDC: reload re-reads idp.jwks_file; azp, revoked users, nested claims ----

    static String b64u(byte[] b) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static byte[] unsigned(java.math.BigInteger n) {
        byte[] b = n.toByteArray();
        return b.length > 1 && b[0] == 0 ? java.util.Arrays.copyOfRange(b, 1, b.length) : b;
    }

    /** A JWKS document with the public halves of these RSA keys, kid by kid. */
    static String jwks(Map<String, java.security.KeyPair> keys) {
        List<Object> out = new ArrayList<>();
        keys.forEach((kid, pair) -> {
            java.security.interfaces.RSAPublicKey pub = (java.security.interfaces.RSAPublicKey) pair.getPublic();
            Map<String, Object> jwk = new LinkedHashMap<>();
            jwk.put("kty", "RSA");
            jwk.put("kid", kid);
            jwk.put("alg", "RS256");
            jwk.put("use", "sig");
            jwk.put("n", b64u(unsigned(pub.getModulus())));
            jwk.put("e", b64u(unsigned(pub.getPublicExponent())));
            out.add(jwk);
        });
        return Json.write(Map.of("keys", out));
    }

    /** An RS256 ID token minted with the JDK. {@code claims} is JSON merged over iss, aud, sub, iat, exp and realm_access.roles = [support]; null removes a claim. */
    static String idToken(java.security.KeyPair pair, String kid, String claims) throws Exception {
        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> body = Json.parseObject("{\"iss\":\"https://idp.example.test\",\"aud\":\"smartdelegate-demo\",\"sub\":\"alice\",\"iat\":" + (now - 5) + ",\"exp\":" + (now + 3600) + ",\"realm_access\":{\"roles\":[\"support\"]}}");
        Json.parseObject(claims).forEach((k, v) -> { if (v == null) body.remove(k); else body.put(k, v); });
        String signed = b64u(("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}").getBytes(StandardCharsets.UTF_8)) + "." + b64u(Json.write(body).getBytes(StandardCharsets.UTF_8));
        java.security.Signature s = java.security.Signature.getInstance("SHA256withRSA");
        s.initSign(pair.getPrivate());
        s.update(signed.getBytes(StandardCharsets.US_ASCII));
        return signed + "." + b64u(s.sign());
    }

    @SuppressWarnings("unchecked")
    static void oidcReload(Path root) throws Exception {
        Path work = Files.createTempDirectory("smartdelegate-java-o-");
        try {
            java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            java.security.KeyPair old = gen.generateKeyPair(), rotated = gen.generateKeyPair();
            Path bundle = work.resolve("bundle"), file = work.resolve("jwks.json");
            Conformance.copyBundle(root, bundle);
            Files.writeString(file, jwks(Map.of("old", old)));
            Map<String, Object> cfg = Conformance.config(root, work.resolve("state"));
            cfg.put("bundle_dir", bundle.toString());
            Map<String, Object> idp = new LinkedHashMap<>();
            idp.put("issuer", "https://idp.example.test");
            idp.put("audience", "smartdelegate-demo");
            idp.put("jwks_file", file.toString());
            idp.put("groups_claim", "realm_access.roles");
            cfg.put("idp", idp);
            String A = "Bearer " + ADMIN;
            try (Engine engine = new Engine(cfg); Server server = Server.listen(engine, "127.0.0.1:0", ADMIN, PEP)) {
                String u = server.url();
                String byOld = idToken(old, "old", "{}"), byNew = idToken(rotated, "new", "{}");
                java.util.function.Function<String, Map<String, Object>> issue = t -> engine.call("issue_token", Json.parseObject("{\"id_token\":\"" + t + "\",\"agent\":\"support-bot\",\"cap\":" + FULL + "}"));
                java.util.function.Predicate<String> accepted = t -> {
                    Map<String, Object> r = issue.apply(t);
                    check(Boolean.TRUE.equals(r.get("ok")) ? "alice".equals(r.get("user")) : "id_token_invalid".equals(err(r).get("code")), "an ID token is accepted for its user or is id_token_invalid: " + Json.write(r));
                    return Boolean.TRUE.equals(r.get("ok"));
                };
                check(accepted.test(byOld) && !accepted.test(byNew), "before the rotation: the old key's token is accepted, the new key's is not");

                // rotate: the file changes, nothing happens until reload
                Files.writeString(file, jwks(Map.of("new", rotated)));
                check(accepted.test(byOld) && !accepted.test(byNew), "a changed jwks_file is not read before reload");
                check(post(u, "/v1/admin/reload", "Bearer " + PEP, "{}").status() == 401 && accepted.test(byOld), "reload needs the admin key");
                Answer reloaded = post(u, "/v1/admin/reload", A, "{}");
                check(reloaded.status() == 200 && Boolean.TRUE.equals(reloaded.body().get("ok")), "reload over REST: " + reloaded);
                check(!accepted.test(byOld) && accepted.test(byNew), "after reload: tokens of the old key are refused, tokens of the new key are accepted");
                Answer viaRest = post(u, "/v1/token", null, "{\"id_token\":\"" + byNew + "\",\"agent\":\"support-bot\",\"cap\":" + FULL + "}");
                check(viaRest.status() == 200 && "alice".equals(viaRest.body().get("user")), "and through the daemon: " + viaRest);

                // a JWKS file that does not load: the error is returned, the keys in force stay
                String good = Files.readString(file);
                String version = (String) engine.call("info", new LinkedHashMap<>()).get("policy_version");
                byte[][] broken = {"{not json".getBytes(StandardCharsets.UTF_8), "[]".getBytes(StandardCharsets.UTF_8), "{}".getBytes(StandardCharsets.UTF_8), "{\"keys\":{}}".getBytes(StandardCharsets.UTF_8),
                        "{\"keys\":null}".getBytes(StandardCharsets.UTF_8), new byte[0], {'{', '"', 'k', (byte) 0xff, '"', ':', '1', '}'}, null};
                for (byte[] content : broken) {
                    if (content == null) Files.delete(file); else Files.write(file, content);
                    Answer r = post(u, "/v1/admin/reload", A, "{}");
                    String what = content == null ? "(file missing)" : new String(content, StandardCharsets.ISO_8859_1);
                    check(r.status() == 400 && r.code().equals("invalid_config") && String.valueOf(err(r.body()).get("message")).startsWith("jwks_file: "), "reload with jwks_file " + what + " is invalid_config: " + r);
                    check(accepted.test(byNew) && !accepted.test(byOld), "and the keys in force are unchanged (" + what + ")");
                }

                // neither is replaced when either fails
                String entities = Files.readString(bundle.resolve("entities.json"));
                Files.writeString(bundle.resolve("entities.json"), entities.replaceFirst("\"region\": \"EU\"", "\"region\": \"US\""));
                Files.writeString(file, "{not json");
                Map<String, Object> r1 = engine.call("reload", new LinkedHashMap<>());
                check("invalid_config".equals(err(r1).get("code")) && version.equals(engine.call("info", new LinkedHashMap<>()).get("policy_version")), "new bundle, broken JWKS: the old bundle stays in force: " + Json.write(r1));
                Files.writeString(bundle.resolve("entities.json"), "not json");
                Files.writeString(file, jwks(Map.of("old", old)));
                Map<String, Object> r2 = engine.call("reload", new LinkedHashMap<>());
                check("entities_parse".equals(err(r2).get("code")) && accepted.test(byNew) && !accepted.test(byOld), "broken bundle, new JWKS: the old keys stay in force: " + Json.write(r2));
                Files.writeString(bundle.resolve("entities.json"), entities.replaceFirst("\"region\": \"EU\"", "\"region\": \"US\""));
                Files.writeString(file, jwks(Map.of("old", old, "new", rotated)));
                Map<String, Object> r3 = engine.call("reload", new LinkedHashMap<>());
                check(Boolean.TRUE.equals(r3.get("ok")) && !version.equals(r3.get("policy_version")) && accepted.test(byNew) && accepted.test(byOld), "both load: both are replaced (two keys during a rotation): " + Json.write(r3));
                Files.writeString(file, good);
                check(Boolean.TRUE.equals(engine.call("reload", new LinkedHashMap<>()).get("ok")) && !accepted.test(byOld), "and the old key can be retired");
                check(!accepted.test(idToken(old, "new", "{}")), "a token signed by the old key under the new kid does not verify");

                // authorised party
                check(accepted.test(idToken(rotated, "new", "{\"azp\":\"smartdelegate-demo\"}")), "azp equal to the audience");
                check(accepted.test(idToken(rotated, "new", "{\"aud\":[\"smartdelegate-demo\"]}")), "one audience in a list, no azp");
                check(accepted.test(idToken(rotated, "new", "{\"aud\":[\"account\",\"smartdelegate-demo\"],\"azp\":\"smartdelegate-demo\"}")), "several audiences, azp ours");
                for (String c : List.of("{\"azp\":\"other-client\"}", "{\"aud\":[\"account\",\"smartdelegate-demo\"],\"azp\":\"other-client\"}", "{\"aud\":[\"account\",\"smartdelegate-demo\"]}", "{\"azp\":[\"smartdelegate-demo\"]}", "{\"azp\":7}"))
                    check(!accepted.test(idToken(rotated, "new", c)), "refused: " + c);
                check("issued to another client (azp)".equals(err(issue.apply(idToken(rotated, "new", "{\"azp\":\"other-client\"}"))).get("message"))
                        && "several audiences and no azp claim".equals(err(issue.apply(idToken(rotated, "new", "{\"aud\":[\"a\",\"smartdelegate-demo\"]}"))).get("message")), "with the reference's messages");

                // nested group claim: top-level name first, then the path; not found is the empty list
                java.util.function.Function<String, Object> roleWith = c -> {
                    try {
                        Map<String, Object> r = engine.call("issue_token", Json.parseObject("{\"id_token\":\"" + idToken(rotated, "new", c) + "\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}"));
                        return Boolean.TRUE.equals(r.get("ok")) ? r.get("role") : err(r).get("code");
                    } catch (Exception e) {
                        throw new AssertionError(e);
                    }
                };
                check("support-agent".equals(roleWith.apply("{\"sub\":\"dave\",\"realm_access\":{\"roles\":[\"support\"]}}")), "realm_access.roles is followed as a path");
                check("role_not_held".equals(roleWith.apply("{\"sub\":\"dave\",\"realm_access\":{\"roles\":[]}}")) && "role_not_held".equals(roleWith.apply("{\"sub\":\"dave\",\"realm_access\":null}"))
                        && "role_not_held".equals(roleWith.apply("{\"sub\":\"dave\",\"realm_access\":{}}")) && "role_not_held".equals(roleWith.apply("{\"sub\":\"dave\",\"realm_access\":\"support\"}")), "a path that is not there is the empty list");
                check("support-agent".equals(roleWith.apply("{\"sub\":\"dave\",\"realm_access.roles\":[\"support\"],\"realm_access\":{\"roles\":[]}}")), "a top-level claim of that exact name wins");
                check("role_not_held".equals(roleWith.apply("{\"sub\":\"dave\",\"realm_access.roles\":[],\"realm_access\":{\"roles\":[\"support\"]}}")), "also when it is empty");
                check("id_token_invalid".equals(roleWith.apply("{\"sub\":\"dave\",\"realm_access\":{\"roles\":{\"support\":true}}}")), "a nested claim of the wrong shape is id_token_invalid");

                // revoked users: an ID token issued at or before the cut-off cannot start a new agent
                long now = System.currentTimeMillis() / 1000;
                Map<String, Object> rev = engine.call("revoke", Json.parseObject("{\"user\":\"alice\",\"by\":\"hr\",\"now\":" + now + "}"));
                check(Long.valueOf(now).equals(rev.get("issued_up_to")), "alice is revoked at " + now + ": " + Json.write(rev));
                Map<String, Object> before = issue.apply(idToken(rotated, "new", "{\"iat\":" + (now - 1) + "}")), at = issue.apply(idToken(rotated, "new", "{\"iat\":" + now + "}"));
                check("id_token_invalid".equals(err(before).get("code")) && "id_token_invalid".equals(err(at).get("code")) && String.valueOf(err(at).get("message")).contains("sign in again"), "sign-ins up to the cut-off are refused: " + Json.write(at));
                check(!accepted.test(idToken(rotated, "new", "{\"iat\":null}")) && !accepted.test(idToken(rotated, "new", "{\"iat\":\"" + (now + 5) + "\"}")) && !accepted.test(idToken(rotated, "new", "{\"iat\":" + (now + 5) + ".5}")), "no iat, or one that is not an integer, is refused for a revoked user");
                check(accepted.test(idToken(rotated, "new", "{\"iat\":" + (now + 1) + "}")), "a sign-in after the cut-off is accepted");
                Map<String, Object> other = engine.call("issue_token", Json.parseObject("{\"id_token\":\"" + idToken(rotated, "new", "{\"sub\":\"dave\",\"iat\":" + (now - 100) + ",\"realm_access\":{\"roles\":[\"support\"]}}") + "\",\"agent\":\"support-bot\",\"role\":\"support-agent\"}"));
                check(Boolean.TRUE.equals(other.get("ok")), "another user is not affected: " + Json.write(other));
                check(Boolean.TRUE.equals(engine.call("audit_verify", new LinkedHashMap<>()).get("ok")), "the audit chain is intact");
            }

            // keys given inline are not a file: reload does not look for one
            Map<String, Object> inline = Conformance.config(root, work.resolve("inline-state"));
            Map<String, Object> idp2 = new LinkedHashMap<>(idp);
            idp2.put("jwks", Json.parseObject(jwks(Map.of("old", old))));
            idp2.put("jwks_file", work.resolve("no-such-file.json").toString());
            inline.put("idp", idp2);
            try (Engine engine = new Engine(inline)) {
                check(Boolean.TRUE.equals(engine.call("reload", new LinkedHashMap<>()).get("ok")), "inline idp.jwks: reload reads no file");
                check(Boolean.TRUE.equals(engine.call("issue_token", Json.parseObject("{\"id_token\":\"" + idToken(old, "old", "{}") + "\",\"agent\":\"support-bot\",\"cap\":" + FULL + "}")).get("ok")), "and the inline keys stay");
            }
        } finally {
            Conformance.rm(work);
        }
        passed("java OIDC: reload re-reads idp.jwks_file (rotation, broken file), azp, revoked users, nested group claim");
    }

    static void all(Path root, List<String> referenceCli) throws Exception {
        restVectors(root);
        keysAndStatus(root);
        concurrency(root, referenceCli);
        commandLine(root, referenceCli);
        oidcReload(root);
        String launcher = System.getProperty("smartdelegate.launcher");
        if (launcher != null && !launcher.isEmpty()) launcher(root, launcher);
        else System.out.println("java launcher: SKIPPED (no -Dsmartdelegate.launcher=PATH)");
    }
}
