package com.jobseekercopilot.authenticationservice.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ServiceIdentityCredentialsTest {

    private static final String SERVICE = "test-only-authentication-service-token-32-bytes";
    private static final String ENVIRONMENT = "test-only-environment-data-token-32-bytes";

    @Test
    void identitiesAreDistinctAndMatchedExactly() {
        var credentials = new ServiceIdentityCredentials(SERVICE, ENVIRONMENT);

        assertTrue(credentials.matchesServiceToken(SERVICE));
        assertTrue(credentials.matchesEnvironmentDataToken(ENVIRONMENT));
        assertFalse(credentials.matchesServiceToken(ENVIRONMENT));
        assertFalse(credentials.matchesServiceToken(null));
        assertFalse(credentials.matchesServiceToken(SERVICE + " "));
    }

    @Test
    void rejectsMissingShortOrSharedValuesWithoutReflectingThem() {
        IllegalStateException missing = assertThrows(IllegalStateException.class,
                () -> new ServiceIdentityCredentials("", ENVIRONMENT));
        IllegalStateException shortToken = assertThrows(IllegalStateException.class,
                () -> new ServiceIdentityCredentials("short-secret", ENVIRONMENT));
        IllegalStateException shared = assertThrows(IllegalStateException.class,
                () -> new ServiceIdentityCredentials(SERVICE, SERVICE));

        assertEquals("Service identity token must contain at least 32 bytes.", missing.getMessage());
        assertEquals(missing.getMessage(), shortToken.getMessage());
        assertEquals("Service and environment-data identity tokens must be distinct.", shared.getMessage());
    }
}
