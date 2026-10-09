// Command-line shim for the Java port, used only by ports/conformance/matrix.py.
// The Java port is a library; this gives it the one command the matrix needs:
//
//   java -cp <classes> Shim call <op> --config FILE [--input JSON|@file|-]
//
// The input defaults to standard input. Output and exit codes follow the other
// ports' CLIs: the result as JSON on stdout; exit 0 ok/allow, 2 deny, 1 error;
// an engine that cannot be built prints "smartdelegate: <code>: <message>" on
// stderr and exits 1. Relative bundle_dir / state_dir are relative to the config file.
import dev.smartdelegate.Engine;
import dev.smartdelegate.Json;
import dev.smartdelegate.SmartDelegateException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public final class Shim {
    private static String fail(String message) {
        System.err.println("smartdelegate: " + message);
        System.exit(1);
        return null;
    }

    public static void main(String[] args) throws Exception {
        String config = null, input = "-";
        for (int i = 2; i + 1 < args.length; i += 2) {
            if (args[i].equals("--config")) config = args[i + 1];
            else if (args[i].equals("--input")) input = args[i + 1];
            else fail("unknown option " + args[i]);
        }
        if (args.length < 2 || args.length % 2 != 0 || !args[0].equals("call") || config == null)
            fail("usage: Shim call <op> --config FILE [--input JSON|@file|-]");
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        try {
            Path file = Path.of(config).toAbsolutePath();
            Map<String, Object> cfg = Json.parseObject(Files.readString(file, StandardCharsets.UTF_8));
            for (String key : new String[] {"bundle_dir", "state_dir"})
                if (cfg.get(key) instanceof String dir) cfg.put(key, file.getParent().resolve(dir).toString());
            String text = input.equals("-") ? new String(System.in.readAllBytes(), StandardCharsets.UTF_8)
                    : input.startsWith("@") ? Files.readString(Path.of(input.substring(1)), StandardCharsets.UTF_8) : input;
            Map<String, Object> payload = Json.parseObject(text.isBlank() ? "{}" : text);
            Map<String, Object> result;
            try (Engine engine = new Engine(cfg)) {
                result = engine.call(args[1], payload);
            }
            out.println(Json.write(result));
            System.exit(!Boolean.TRUE.equals(result.get("ok")) ? 1 : "deny".equals(result.get("effect")) ? 2 : 0);
        } catch (SmartDelegateException e) {
            fail(e.code() + ": " + e.detail());
        } catch (java.io.IOException | RuntimeException e) {
            fail("shim: " + e);
        }
    }
}
