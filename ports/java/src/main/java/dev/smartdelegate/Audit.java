package dev.smartdelegate;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Append-only, hash-chained decision log (JSON Lines), byte-compatible with
 * the other ports: record.hash = sha256(prev + canonical_json(record without "hash")).
 */
final class Audit {
    static final String GENESIS = "0".repeat(64);

    final Path path;
    long seq = 0;
    String head = GENESIS;
    long len = 0;

    Audit(Path path) {
        this.path = path;
        if (Files.exists(path)) {
            Map<String, Object> v = verify(path);
            seq = (Long) v.get("records");
            head = (String) v.get("head");
            try {
                len = Files.size(path);
            } catch (IOException e) {
                throw new EngineException("audit_io", "cannot read audit log: " + e.getMessage());
            }
        }
    }

    /**
     * A record ends at "\n" and nowhere else: canonical JSON writes U+2028,
     * U+2029 and U+0085 as themselves, and they are data, not line breaks.
     */
    static String[] lines(String text) {
        return text.split("\n", -1);
    }

    /** Empty or only whitespace, by the reference's definition of whitespace (Unicode, including U+0085 and no-break spaces). */
    static boolean blank(String line) {
        return line.codePoints().allMatch(c -> Character.isWhitespace(c) || Character.isSpaceChar(c) || c == 0x85);
    }

    static Map<String, Object> verify(Path path) {
        String prev = GENESIS;
        long n = 0;
        byte[] raw;
        try {
            raw = Files.readAllBytes(path);
        } catch (IOException e) {
            throw new EngineException("audit_io", "cannot read audit log: " + e.getMessage());
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException e) {
            throw new EngineException("audit_broken", "the audit log is not UTF-8");
        }
        String[] lines = lines(text);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (blank(line)) continue;
            int lineno = i + 1;
            Map<String, Object> rec;
            try {
                rec = Json.parseObject(line);
            } catch (RuntimeException e) {
                throw new EngineException("audit_broken", "line " + lineno + ": not JSON");
            }
            Object claimed = rec.remove("hash");
            if (!prev.equals(rec.get("prev"))) throw new EngineException("audit_broken", "line " + lineno + ": prev hash does not match the line before");
            if (!Long.valueOf(n + 1).equals(rec.get("seq"))) throw new EngineException("audit_broken", "line " + lineno + ": sequence number is not " + (n + 1));
            String actual;
            try {
                actual = Crypto.sha256Hex(prev + Json.canon(rec));
            } catch (IllegalArgumentException e) {
                throw new EngineException("audit_broken", "line " + lineno + ": content does not match its hash");
            }
            if (!actual.equals(claimed)) throw new EngineException("audit_broken", "line " + lineno + ": content does not match its hash");
            prev = actual;
            n++;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("records", n);
        out.put("head", prev);
        return out;
    }

    static List<Object> tail(Path path, int n) {
        List<Object> out = new ArrayList<>();
        if (!Files.exists(path)) return out;
        try {
            List<String> lines = new ArrayList<>();
            // lenient decoding: tail shows what it can; audit_verify is the judge
            for (String l : lines(new String(Files.readAllBytes(path), StandardCharsets.UTF_8))) if (!blank(l)) lines.add(l);
            for (String l : lines.subList(Math.max(0, lines.size() - n), lines.size())) {
                try { out.add(Json.parse(l)); } catch (RuntimeException ignored) { }
            }
        } catch (IOException e) {
            throw new EngineException("audit_io", "cannot read audit log: " + e.getMessage());
        }
        return out;
    }

    /** Chain onto the last record if another process appended. */
    private void resync() throws IOException {
        long size = Files.exists(path) ? Files.size(path) : 0;
        if (size == len) return;
        if (size == 0) throw new EngineException("audit_broken", "the audit log was truncated while in use");
        String last = null;
        for (String l : lines(new String(Files.readAllBytes(path), StandardCharsets.UTF_8))) if (!blank(l)) last = l;
        try {
            Map<String, Object> rec = Json.parseObject(last);
            seq = (Long) rec.get("seq");
            head = (String) rec.get("hash");
            len = size;
            if (head == null) throw new IllegalArgumentException();
        } catch (RuntimeException e) {
            throw new EngineException("audit_broken", "the last audit record is unreadable");
        }
    }

    String append(Map<String, Object> record, long ts) {
        try {
            resync();
            Map<String, Object> rec = new LinkedHashMap<>(record);
            rec.remove("hash");
            rec.put("seq", seq + 1);
            rec.put("ts", ts);
            rec.put("prev", head);
            String h = Crypto.sha256Hex(head + Json.canon(rec));
            rec.put("hash", h);
            Files.write(path, (Json.canon(rec) + "\n").getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            len = Files.size(path);
            seq++;
            head = h;
            return h;
        } catch (IOException e) {
            throw new EngineException("audit_io", "cannot write audit log: " + e.getMessage());
        }
    }
}
