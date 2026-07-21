package com.jobseekercopilot.authenticationservice.exception;

public class RefreshTokenException extends RuntimeException {

    private final String code;

    private RefreshTokenException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public static RefreshTokenException invalid() {
        return new RefreshTokenException("REFRESH_TOKEN_INVALID", "The refresh token is invalid or expired.");
    }

    public static RefreshTokenException reused() {
        return new RefreshTokenException("REFRESH_TOKEN_REUSED",
                "Refresh token reuse was detected; the session has been revoked.");
    }
}
