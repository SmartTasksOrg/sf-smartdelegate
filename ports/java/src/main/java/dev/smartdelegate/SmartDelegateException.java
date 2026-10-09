package dev.smartdelegate;

/** The request was malformed or could not be processed. A deny is not an exception of this type. */
public class SmartDelegateException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    private final String detail;

    public SmartDelegateException(String code, String message) {
        super(code + ": " + message);
        this.code = code;
        this.detail = message;
    }

    /** The message without the code prefix. */
    public String detail() {
        return detail;
    }

    public String code() {
        return code;
    }
}
