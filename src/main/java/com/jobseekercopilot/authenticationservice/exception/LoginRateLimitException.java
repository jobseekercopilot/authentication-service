package com.jobseekercopilot.authenticationservice.exception;

public class LoginRateLimitException extends RuntimeException {

    private final long retryAfterSeconds;

    public LoginRateLimitException(long retryAfterSeconds) {
        super("Too many authentication attempts. Try again later.");
        this.retryAfterSeconds = Math.max(1, retryAfterSeconds);
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
