package pl.dss.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import pl.dss.validation.DocumentValidationException;

@RestControllerAdvice
public class ValidationExceptionHandler {
    private static final Logger LOG = LoggerFactory.getLogger(ValidationExceptionHandler.class);

    @ExceptionHandler(DocumentValidationException.class)
    public ProblemDetail validationError(DocumentValidationException exception) {
        HttpStatus status = switch (exception.getCode()) {
            case EMPTY_FILE -> HttpStatus.BAD_REQUEST;
            case UPLOAD_TOO_LARGE -> HttpStatus.PAYLOAD_TOO_LARGE;
            case UNSUPPORTED_OR_UNRECOGNIZED_DOCUMENT -> HttpStatus.UNSUPPORTED_MEDIA_TYPE;
            case MALFORMED_DOCUMENT -> HttpStatus.UNPROCESSABLE_ENTITY;
            case FILE_READ_ERROR, VALIDATION_ERROR, INCONSISTENT_DSS_REPORT -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
        if (status.is5xxServerError()) {
            LOG.error("Document validation failed ({})", exception.getCode(), exception);
        }
        return problem(status, exception.getCode().name(), exception.getMessage());
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ProblemDetail uploadLimit(MaxUploadSizeExceededException exception) {
        return problem(HttpStatus.PAYLOAD_TOO_LARGE, "UPLOAD_TOO_LARGE", "Multipart upload limit exceeded");
    }

    @ExceptionHandler(MissingServletRequestPartException.class)
    public ProblemDetail missingFile(MissingServletRequestPartException exception) {
        return problem(HttpStatus.BAD_REQUEST, "MISSING_FILE", "Required multipart part 'file' is missing");
    }

    private static ProblemDetail problem(HttpStatus status, String code, String message) {
        var detail = ProblemDetail.forStatusAndDetail(status, message);
        detail.setTitle(code);
        detail.setProperty("code", code);
        return detail;
    }
}
