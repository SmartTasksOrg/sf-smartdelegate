package dev.smartdelegate;

import java.util.LinkedHashMap;
import java.util.Map;

/** A request that could not be processed. Becomes {"ok": false, "error": {code, message, rule}}; never an allow. */
public class EngineException extends SmartDelegateException {
    private static final long serialVersionUID = 1L;

    public EngineException(String code, String message) {
        super(code, message);
    }

    /** The rule id of a decision reason or error code: {@code policy_forbid} -> {@code DELEGATE-POLICY-FORBID}. */
    public static String ruleId(String code) {
        return "DELEGATE-" + String.valueOf(code).toUpperCase(java.util.Locale.ROOT).replace('_', '-');
    }

    public Map<String, Object> toJson() {
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("code", code());
        err.put("message", detail());
        err.put("rule", ruleId(code()));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", false);
        out.put("error", err);
        return out;
    }
}
