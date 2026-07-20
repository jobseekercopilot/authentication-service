package com.jobseekercopilot.authenticationservice.exception;

import com.jobseekercopilot.authenticationservice.logging.CorrelationIdFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void redactsUnexpectedExceptionAndIncludesCorrelationId() {
        MDC.put(CorrelationIdFilter.MDC_KEY, "correlation-123");

        var response = handler.handleGeneralException(
                new IllegalStateException("database password and parser detail"));

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("1", response.getBody().schemaVersion());
        assertEquals("INTERNAL_ERROR", response.getBody().code());
        assertEquals("An unexpected error occurred.", response.getBody().message());
        assertEquals("correlation-123", response.getBody().correlationId());
        assertFalse(response.getBody().toString().contains("password"));
        assertFalse(response.getBody().toString().contains("parser"));
    }

    @Test
    void mapsCredentialFailureToUniformStableResponse() {
        var response = handler.handleUnauthorized();

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("AUTHENTICATION_FAILED", response.getBody().code());
        assertEquals("Invalid email or password.", response.getBody().message());
    }
}
