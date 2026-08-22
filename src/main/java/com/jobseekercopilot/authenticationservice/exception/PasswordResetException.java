package com.jobseekercopilot.authenticationservice.exception;

public class PasswordResetException extends RuntimeException {
    private static final String SAFE_MESSAGE =
            "This password-reset link is invalid or has expired.";

    private PasswordResetException() {
        super(SAFE_MESSAGE);
    }

    public static PasswordResetException invalid() {
        return new PasswordResetException();
    }

    public String getCode() {
        return "PASSWORD_RESET_LINK_INVALID";
    }
}
