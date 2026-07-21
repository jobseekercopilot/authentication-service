package com.jobseekercopilot.authenticationservice.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ServiceIdentityCredentials {

    static final int MINIMUM_TOKEN_BYTES = 32;

    private final byte[] serviceToken;
    private final byte[] environmentDataToken;

    public ServiceIdentityCredentials(
            @Value("${service.identity.token}") String serviceToken,
            @Value("${service.identity.environment-data-token}") String environmentDataToken) {
        this.serviceToken = validate(serviceToken, "Service identity token");
        this.environmentDataToken = validate(environmentDataToken, "Environment-data identity token");
        if (MessageDigest.isEqual(this.serviceToken, this.environmentDataToken)) {
            throw new IllegalStateException("Service and environment-data identity tokens must be distinct.");
        }
    }

    public boolean matchesServiceToken(String candidate) {
        return matches(serviceToken, candidate);
    }

    public boolean matchesEnvironmentDataToken(String candidate) {
        return matches(environmentDataToken, candidate);
    }

    private static byte[] validate(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(label + " must contain at least 32 bytes.");
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < MINIMUM_TOKEN_BYTES) {
            throw new IllegalStateException(label + " must contain at least 32 bytes.");
        }
        return bytes;
    }

    private static boolean matches(byte[] expected, String candidate) {
        if (candidate == null) {
            return false;
        }
        return MessageDigest.isEqual(expected, candidate.getBytes(StandardCharsets.UTF_8));
    }
}
