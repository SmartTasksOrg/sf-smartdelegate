package dev.smartdelegate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Build-time only: exercises the engine, the daemon and the client once on a
 * throwaway bundle, so that {@code build.sh} can record the classes a normal
 * run loads into a class-data archive ({@code -XX:ArchiveClassesAtExit}).
 * Nothing here decides anything; results are ignored.
 */
final class Warmup {
    private Warmup() {}

    public static void main(String[] args) throws IOException {
        Path dir = Files.createTempDirectory("smartdelegate-warmup-");
        try {
            Path bundle = Files.createDirectories(dir.resolve("bundle"));
            Files.writeString(bundle.resolve("policies.json"),
                    "{\"policies\":{\"all\":{\"effect\":\"permit\",\"principal\":{\"op\":\"All\"},\"action\":{\"op\":\"All\"},\"resource\":{\"op\":\"All\"},\"conditions\":[]}}}", StandardCharsets.UTF_8);
            Files.writeString(bundle.resolve("entities.json"), "[{\"uid\":{\"type\":\"User\",\"id\":\"u\"},\"attrs\":{},\"parents\":[]},{\"uid\":{\"type\":\"Agent\",\"id\":\"a\"},\"attrs\":{},\"parents\":[]}]", StandardCharsets.UTF_8);
            Files.writeString(bundle.resolve("catalog.json"), "{\"resources\":{\"crm.customer\":{\"entity_type\":\"Customer\",\"fields\":{\"email\":{\"labels\":[\"pii\"],\"mask\":\"redact\"}}}}}", StandardCharsets.UTF_8);
            Map<String, Object> cfg = new LinkedHashMap<>();
            cfg.put("bundle_dir", bundle.toString());
            cfg.put("state_dir", dir.resolve("state").toString());
            String key = "warmup-key-0123456789abcdef";
            try (Engine engine = new Engine(cfg); Server server = Server.listen(engine, "127.0.0.1:0", key, key)) {
                Client client = new Client(server.url(), key, key);
                Map<String, Object> cap = Json.parseObject("{\"actions\":[\"read\"],\"resources\":[\"crm.customer/*\"],\"budget\":{\"EUR\":100}}");
                Map<String, Object> t = client.call("issue_token", new LinkedHashMap<>(Map.of("user", "u", "agent", "a", "cap", cap)));
                Object token = t.get("token") != null ? t.get("token") : "";
                Map<String, Object> request = Json.parseObject("{\"action\":\"read\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"c-1\"},\"data\":{\"email\":\"x@example.com\"}}");
                request.put("token", token);
                for (String op : List.of("authorize", "filter", "explain", "inspect_token")) client.call(op, request);
                client.call("exchange_token", new LinkedHashMap<>(Map.of("subject_token", token, "actor", "a")));
                client.call("revoke", new LinkedHashMap<>(Map.of("token", token, "by", "warmup")));
                for (String op : List.of("info", "approvals", "audit_verify", "audit_tail")) client.call(op, new LinkedHashMap<>());
                if (args.length > 0) System.out.println(Json.pretty(t));
                Json.pretty(engine.call("info", new LinkedHashMap<>()));
            }
            Vectors.subset(cfg, cfg, "");
            // the command line's own classes
            java.io.PrintStream sink = new java.io.PrintStream(java.io.OutputStream.nullOutputStream(), false, StandardCharsets.UTF_8);
            for (String[] argv : new String[][] {{"info"}, {"audit", "tail"}, {"audit", "verify"}, {"approvals"}, {"policy", "check"}, {"--version"}})
                Cli.run(java.util.stream.Stream.concat(java.util.Arrays.stream(argv), Stream.of("--bundle", bundle.toString(), "--state", dir.resolve("state").toString())).toArray(String[]::new),
                        java.io.InputStream.nullInputStream(), sink, sink, Map.of());
        } catch (RuntimeException e) {
            if (args.length > 0) throw e;
        } finally {
            try (Stream<Path> walk = Files.walk(dir)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }
}
