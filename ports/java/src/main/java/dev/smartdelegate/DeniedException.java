package dev.smartdelegate;

import java.util.Map;

/** Thrown by {@link Client#require} when the decision is deny. */
public class DeniedException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final transient Map<String, Object> decision;

    public DeniedException(Map<String, Object> decision) {
        super("denied by SmartDelegate (" + decision.get("reason") + "): " + decision.getOrDefault("detail", ""));
        this.decision = decision;
    }

    public Map<String, Object> decision() {
        return decision;
    }

    public String reason() {
        return String.valueOf(decision.get("reason"));
    }

    /** Non-null when a human can approve the held request. */
    @SuppressWarnings("unchecked")
    public String approvalId() {
        Object a = decision.get("approval");
        return a instanceof Map ? (String) ((Map<String, Object>) a).get("id") : null;
    }
}
