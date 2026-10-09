package dev.smartdelegate;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * REST decision daemon ({@code serve}). A port of src/sf_smartdelegate/daemon.py
 * on the JDK's own {@code com.sun.net.httpserver}; see spec/openapi.yaml.
 *
 * Two keys guard it:
 * <pre>
 *   pep key    enforcement points: /v1/authorize, /v1/filter, /v1/explain,
 *              /v1/obligations/apply, /v1/token/inspect, /v1/info
 *   admin key  /v1/admin/* and issuing a root token without an OIDC ID token
 * </pre>
 * {@code /v1/token} needs no key for token exchange (holding the parent token
 * is the authority) or for issuance backed by a verified OIDC ID token. TLS
 * is not terminated here: bind to loopback or put it behind a mesh.
 *
 * Requests run on a pool of at most {@value #THREADS} threads; the engine
 * serialises its own calls, so decisions are made one at a time whatever the
 * pool size. A peer that stops sending in the middle of a request holds one
 * of those threads until the JDK server gives up on it ({@value #MAX_REQUEST_SECONDS}
 * seconds unless {@code sun.net.httpserver.maxReqTime} says otherwise).
 * Anything that goes wrong in a handler is answered with a JSON error, never
 * with a 200.
 */
public final class Server implements AutoCloseable {
    /** The largest request body the daemon reads. */
    public static final int MAX_BODY = 8 * 1024 * 1024;
    static final int THREADS = 256;
    static final int MAX_REQUEST_SECONDS = 30;

    private static final Map<String, String[]> ROUTES = new LinkedHashMap<>();

    static {
        ROUTES.put("GET /v1/info", new String[] {"info", "pep"});
        ROUTES.put("POST /v1/authorize", new String[] {"authorize", "pep"});
        ROUTES.put("POST /v1/filter", new String[] {"filter", "pep"});
        ROUTES.put("POST /v1/explain", new String[] {"explain", "pep"});
        ROUTES.put("POST /v1/obligations/apply", new String[] {"apply_obligations", "pep"});
        ROUTES.put("POST /v1/token/inspect", new String[] {"inspect_token", "pep"});
        ROUTES.put("POST /v1/admin/revoke", new String[] {"revoke", "admin"});
        ROUTES.put("POST /v1/admin/approve", new String[] {"approve", "admin"});
        ROUTES.put("POST /v1/admin/reload", new String[] {"reload", "admin"});
        ROUTES.put("GET /v1/admin/approvals", new String[] {"approvals", "admin"});
        ROUTES.put("GET /v1/admin/audit/verify", new String[] {"audit_verify", "admin"});
        ROUTES.put("GET /v1/admin/audit/tail", new String[] {"audit_tail", "admin"});
    }

    /**
     * The JDK server reads these once, when its classes load. They are set
     * here only when the operator has not set them:
     * nodelay, because headers and body go out as two writes and Nagle's
     * algorithm would hold the second for the peer's delayed ACK (40 ms on
     * every call); maxReqTime / maxRspTime (seconds), because the JDK's
     * default is to wait for ever for the rest of a request, on a pool thread.
     */
    private static void defaults() {
        String limit = String.valueOf(MAX_REQUEST_SECONDS);
        for (String[] kv : new String[][] {{"sun.net.httpserver.nodelay", "true"}, {"sun.net.httpserver.maxReqTime", limit}, {"sun.net.httpserver.maxRspTime", limit}}) {
            try {
                if (System.getProperty(kv[0]) == null) System.setProperty(kv[0], kv[1]);
            } catch (SecurityException ignored) {
                // the JDK's own defaults then apply
            }
        }
    }

    private final HttpServer http;
    private final ExecutorService pool;
    private final String url;

    private Server(HttpServer http, ExecutorService pool) {
        this.http = http;
        this.pool = pool;
        InetSocketAddress a = http.getAddress();
        this.url = "http://" + a.getAddress().getHostAddress() + ":" + a.getPort();
    }

    /** "http://host:port" of the bound address. */
    public String url() {
        return url;
    }

    public int port() {
        return http.getAddress().getPort();
    }

    /** "host:port"; an empty host is 127.0.0.1, and port 0 asks the system for a free one. Throws {@link EngineException} {@code invalid_config}. */
    public static InetSocketAddress listenAddress(String text) {
        int i = text.lastIndexOf(':');
        String host = i >= 0 ? text.substring(0, i) : "", port = i >= 0 ? text.substring(i + 1) : text;
        if (host.isEmpty()) host = "127.0.0.1";
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        int n;
        try {
            n = port.matches("[0-9]{1,5}") ? Integer.parseInt(port) : -1;
        } catch (NumberFormatException e) {
            n = -1;
        }
        if (n < 0 || n > 65535) throw new EngineException("invalid_config", "listen address '" + text + "': the port must be a number");
        try {
            return new InetSocketAddress(InetAddress.getByName(host), n);
        } catch (IOException e) {
            throw new EngineException("invalid_config", "listen address '" + text + "': unknown host");
        }
    }

    /**
     * Bind and start answering. Both keys must be 16 characters or longer.
     * The engine stays the caller's: {@link #close()} stops the daemon and
     * leaves the engine open. Throws {@link EngineException}
     * ({@code invalid_config}; {@code daemon_io} when the address cannot be bound).
     */
    public static Server listen(Engine engine, String listen, String adminKey, String pepKey) {
        if (engine == null) throw new EngineException("invalid_config", "serve needs an engine");
        if (adminKey == null || pepKey == null || adminKey.length() < 16 || pepKey.length() < 16)
            throw new EngineException("invalid_config", "serve needs admin_key and pep_key (16+ characters) in the config or SMARTDELEGATE_ADMIN_KEY / SMARTDELEGATE_PEP_KEY");
        InetSocketAddress address = listenAddress(listen);
        defaults();
        HttpServer http;
        try {
            http = HttpServer.create(address, 128);
        } catch (IOException e) {
            throw new EngineException("daemon_io", "cannot listen on " + listen + ": " + e.getMessage());
        }
        AtomicInteger n = new AtomicInteger();
        ThreadPoolExecutor pool = new ThreadPoolExecutor(THREADS, THREADS, 30, TimeUnit.SECONDS, new LinkedBlockingQueue<>(), r -> {
            Thread t = new Thread(r, "smartdelegate-http-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
        pool.allowCoreThreadTimeOut(true);
        byte[] admin = adminKey.getBytes(StandardCharsets.UTF_8), pep = pepKey.getBytes(StandardCharsets.UTF_8);
        http.createContext("/", x -> handle(x, engine, admin, pep));
        http.setExecutor(pool);
        http.start();
        return new Server(http, pool);
    }

    /** Stop accepting and drop open connections. */
    @Override
    public void close() {
        http.stop(0);
        pool.shutdownNow();
    }

    // ---- one request -----------------------------------------------------------

    private static Map<String, Object> error(String code, String message) {
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("code", code);
        err.put("message", message);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", false);
        out.put("error", err);
        return out;
    }

    /** Constant time for keys of equal length; the comparison is over the UTF-8 bytes, as in the reference. */
    private static boolean sameKey(byte[] given, byte[] key) {
        return MessageDigest.isEqual(given, key);
    }

    private static void send(HttpExchange x, int status, Map<String, Object> body, boolean close) throws IOException {
        // ASCII only, like the reference: the bytes are valid whatever a string holds
        byte[] raw = Json.format(body, 0, true).getBytes(StandardCharsets.US_ASCII);
        x.getResponseHeaders().set("Content-Type", "application/json");
        x.getResponseHeaders().set("Server", "smartdelegate");
        if (close) x.getResponseHeaders().set("Connection", "close");
        if (x.getRequestMethod().equals("HEAD")) {
            x.sendResponseHeaders(status, -1);
            return;
        }
        x.sendResponseHeaders(status, raw.length);
        try (OutputStream out = x.getResponseBody()) {
            out.write(raw);
        }
    }

    /** At most {@code limit} bytes, or null when the stream holds more. */
    private static byte[] readUpTo(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        for (int n; (n = in.read(buf)) >= 0; ) {
            if (out.size() + n > limit) return null;
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /**
     * A body that is refused is not read: the answer goes out at once, with
     * {@code Connection: close}. The JDK server then waits for the peer to
     * hang up, or for maxReqTime, before it frees the connection.
     */
    private static void tooLarge(HttpExchange x) throws IOException {
        send(x, 400, error("invalid_input", "request body is too large"), true);
    }

    private static boolean blank(byte[] raw) {
        for (byte b : raw) if (b != ' ' && b != '\t' && b != '\n' && b != '\r' && b != 0x0b && b != 0x0c) return false;
        return true;
    }

    /** The request body as JSON. Strict UTF-8; an empty or blank body is {@code {}}. */
    private static Object parseBody(byte[] raw) throws CharacterCodingException {
        if (blank(raw)) return new LinkedHashMap<String, Object>();
        String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw)).toString();
        return Json.parse(text.startsWith("﻿") ? text.substring(1) : text);
    }

    private static void handle(HttpExchange x, Engine engine, byte[] admin, byte[] pep) {
        try {
            respond(x, engine, admin, pep);
        } catch (Throwable t) {
            // fail closed: a bug or an exhausted resource is an error answer, never a 200
            try {
                send(x, 500, error("internal", t.getClass().getSimpleName()), true);
            } catch (IOException | RuntimeException ignored) {
                // the answer had already started, or the peer is gone
            }
        } finally {
            x.close();
        }
    }

    @SuppressWarnings("unchecked")
    private static void respond(HttpExchange x, Engine engine, byte[] admin, byte[] pep) throws IOException {
        String method = x.getRequestMethod();
        if (!method.equals("GET") && !method.equals("POST")) {
            send(x, 501, error("unsupported_method", "only GET and POST are supported"), true);
            return;
        }
        // the request target as sent: no percent-decoding, as in the reference
        String target = x.getRequestURI().toString();
        if (target.startsWith("//")) target = "/" + target.replaceFirst("^/+", "");   // the reference collapses leading slashes
        int q = target.indexOf('?');
        String path = q >= 0 ? target.substring(0, q) : target, query = q >= 0 ? target.substring(q + 1) : "";
        if (path.equals("/healthz")) {
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("ok", true);
            send(x, 200, ok, false);
            return;
        }
        Object body = new LinkedHashMap<String, Object>();
        if (method.equals("POST")) {
            String problem = null;
            String declared = x.getRequestHeaders().getFirst("Content-Length");
            long length = -1;
            if (declared != null) {
                try {
                    length = Long.parseLong(declared.strip());
                } catch (NumberFormatException e) {
                    problem = "bad Content-Length";
                }
            }
            if (problem == null && length > MAX_BODY) {
                tooLarge(x);
                return;
            }
            if (problem == null) {
                byte[] raw = readUpTo(x.getRequestBody(), MAX_BODY);   // also bounds a chunked body, which declares no length
                if (raw == null) {
                    tooLarge(x);
                    return;
                }
                try {
                    body = parseBody(raw);
                } catch (CharacterCodingException | RuntimeException | StackOverflowError e) {
                    problem = "body is not JSON";
                }
            }
            if (problem != null) {
                send(x, 400, error("invalid_input", problem), false);
                return;
            }
        }
        String auth = x.getRequestHeaders().getFirst("Authorization");
        byte[] key = (auth != null && auth.startsWith("Bearer ") ? auth.substring(7).strip() : "").getBytes(StandardCharsets.UTF_8);
        boolean isAdmin = sameKey(key, admin);
        boolean isPep = sameKey(key, pep) | isAdmin;
        String op;
        boolean allowed;
        String[] route = ROUTES.get(method + " " + path);
        if (method.equals("POST") && path.equals("/v1/token")) {
            Map<String, Object> m = body instanceof Map ? (Map<String, Object>) body : null;
            if (m != null && m.containsKey("subject_token")) {
                op = "exchange_token";
                allowed = true;
            } else if (m != null && m.containsKey("id_token")) {
                Map<String, Object> stripped = new LinkedHashMap<>(m);
                stripped.remove("user");   // identity comes from the ID token alone
                body = stripped;
                op = "issue_token";
                allowed = true;
            } else {
                op = "issue_token";
                allowed = isAdmin;
            }
        } else if (route != null) {
            op = route[0];
            allowed = route[1].equals("admin") ? isAdmin : isPep;
            if (op.equals("audit_tail")) {
                long n = 20;
                for (String kv : query.split("&")) {
                    if (kv.startsWith("n=")) {
                        String v = kv.substring(2);
                        if (v.matches("[0-9]+")) n = v.length() > 9 ? Integer.MAX_VALUE : Long.parseLong(v);
                        break;
                    }
                }
                Map<String, Object> tail = new LinkedHashMap<>();
                tail.put("n", n);
                body = tail;
            }
        } else {
            send(x, 404, error("not_found", "no such endpoint"), false);
            return;
        }
        if (!allowed) {
            send(x, 401, error("unauthorized", "missing or wrong API key"), false);
            return;
        }
        // a body that is not an object is the engine's to refuse (invalid_input)
        Map<String, Object> result = engine.call(op, body instanceof Map ? (Map<String, Object>) body : null);
        send(x, Boolean.TRUE.equals(result.get("ok")) ? 200 : 400, result, false);
    }
}
