package com.jobseekercopilot.authenticationservice.exception;

public class LegalAcceptanceException extends RuntimeException {

    private final String code;

    private LegalAcceptanceException(String code, String message) {
        super(message);
        this.code = code;
    }

    public static LegalAcceptanceException required() {
        return new LegalAcceptanceException(
                "LEGAL_ACCEPTANCE_REQUIRED",
                "Accept the Terms of Use, acknowledge the Privacy Notice and confirm you are at least 18.");
    }

    public static LegalAcceptanceException outdated() {
        return new LegalAcceptanceException(
                "LEGAL_VERSION_OUTDATED",
                "Review the current Terms of Use and Privacy Notice before registering.");
    }

    public String getCode() {
        return code;
    }
}
