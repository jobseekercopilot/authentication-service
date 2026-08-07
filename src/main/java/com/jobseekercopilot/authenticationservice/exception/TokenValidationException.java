package com.jobseekercopilot.authenticationservice.exception;

public class TokenValidationException extends RuntimeException {

    private final String code;

    public TokenValidationException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public static TokenValidationException required() {
        return new TokenValidationException("TOKEN_REQUIRED", "A Bearer token is required.");
    }

    public static TokenValidationException expired() {
        return new TokenValidationException("TOKEN_EXPIRED", "The authentication token has expired.");
    }

    public static TokenValidationException malformed() {
        return new TokenValidationException("TOKEN_MALFORMED", "The authentication token is malformed.");
    }

    public static TokenValidationException unsupported() {
        return new TokenValidationException("TOKEN_UNSUPPORTED", "The authentication token is unsupported.");
    }

    public static TokenValidationException invalid() {
        return new TokenValidationException("TOKEN_INVALID", "The authentication token is invalid.");
    }

    public static TokenValidationException recentAuthenticationRequired() {
        return new TokenValidationException(
                "RECENT_AUTHENTICATION_REQUIRED",
                "Sign in again before exporting or deleting account data.");
    }
}
