package pl.dss.validation;

public class DocumentValidationException extends RuntimeException {
    public enum Code {
        EMPTY_FILE,
        UPLOAD_TOO_LARGE,
        FILE_READ_ERROR,
        UNSUPPORTED_OR_UNRECOGNIZED_DOCUMENT,
        MALFORMED_DOCUMENT,
        VALIDATION_ERROR,
        INCONSISTENT_DSS_REPORT
    }

    private final Code code;

    public DocumentValidationException(Code code, String message) {
        super(message);
        this.code = code;
    }

    public DocumentValidationException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code getCode() {
        return code;
    }
}
