package com.jobseekercopilot.authenticationservice.exception;

import com.jobseekercopilot.authenticationservice.logging.CorrelationIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ErrorResponse> handleBadRequest() {
        return response(HttpStatus.BAD_REQUEST, "REQUEST_VALIDATION_FAILED", "Request validation failed.");
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleMalformedJson() {
        return response(HttpStatus.BAD_REQUEST, "MALFORMED_JSON", "Request body is not valid JSON.");
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorized() {
        return response(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_FAILED", "Invalid email or password.");
    }

    @ExceptionHandler(TokenValidationException.class)
    public ResponseEntity<ErrorResponse> handleTokenValidation(TokenValidationException exception) {
        return response(HttpStatus.UNAUTHORIZED, exception.getCode(), exception.getMessage());
    }

    @ExceptionHandler(RefreshTokenException.class)
    public ResponseEntity<ErrorResponse> handleRefreshToken(RefreshTokenException exception) {
        return response(HttpStatus.UNAUTHORIZED, exception.getCode(), exception.getMessage());
    }

    @ExceptionHandler(LoginRateLimitException.class)
    public ResponseEntity<ErrorResponse> handleLoginRateLimit(LoginRateLimitException exception) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, Long.toString(exception.getRetryAfterSeconds()))
                .body(error("TOO_MANY_AUTHENTICATION_ATTEMPTS",
                        "Too many authentication attempts. Try again later."));
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ErrorResponse> handleConflict() {
        return response(HttpStatus.CONFLICT, "ACCOUNT_ALREADY_EXISTS",
                "An account with this email already exists.");
    }

    @ExceptionHandler(PasswordResetException.class)
    public ResponseEntity<ErrorResponse> handlePasswordReset(PasswordResetException exception) {
        return response(HttpStatus.BAD_REQUEST, exception.getCode(), exception.getMessage());
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound() {
        return response(HttpStatus.NOT_FOUND, "NOT_FOUND", "The requested resource was not found.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneralException(Exception exception) {
        log.error("Unhandled authentication request failure error={}", exception.getClass().getSimpleName());
        return response(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An unexpected error occurred.");
    }

    private ResponseEntity<ErrorResponse> response(HttpStatus status, String code, String message) {
        return ResponseEntity.status(status).body(error(code, message));
    }

    private ErrorResponse error(String code, String message) {
        return new ErrorResponse(code, message, MDC.get(CorrelationIdFilter.MDC_KEY));
    }
}
