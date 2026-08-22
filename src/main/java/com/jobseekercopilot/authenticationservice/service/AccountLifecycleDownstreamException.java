package com.jobseekercopilot.authenticationservice.service;

public class AccountLifecycleDownstreamException extends RuntimeException {

    private final String safeCode;

    public AccountLifecycleDownstreamException(String safeCode, Throwable cause) {
        super(safeCode, cause);
        this.safeCode = safeCode;
    }

    public String getSafeCode() {
        return safeCode;
    }
}
