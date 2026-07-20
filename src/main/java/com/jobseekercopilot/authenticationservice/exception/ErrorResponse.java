package com.jobseekercopilot.authenticationservice.exception;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
        String schemaVersion,
        String code,
        String message,
        String correlationId,
        Instant timestamp) {

    public static final String SCHEMA_VERSION = "1";

    public ErrorResponse(String code, String message, String correlationId) {
        this(SCHEMA_VERSION, code, message, correlationId, Instant.now());
    }
}
