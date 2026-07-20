package com.jobseekercopilot.authenticationservice.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordEncoderCompatibilityTest {

    private static final String PASSWORD = "A-valid-local password 2026!";
    private final PasswordEncoder encoder = new AuthConfig().passwordEncoder();

    @Test
    void newlyEncodedPasswordsUsePbkdf2() {
        String encoded = encoder.encode(PASSWORD);

        assertTrue(encoded.startsWith("{pbkdf2}"));
        assertTrue(encoder.matches(PASSWORD, encoded));
        assertFalse(encoder.matches("wrong-password", encoded));
    }

    @Test
    void legacyUnprefixedBcryptHashesRemainVerifiableForMigration() {
        String legacyHash = new BCryptPasswordEncoder().encode(PASSWORD);

        assertTrue(encoder.matches(PASSWORD, legacyHash));
        assertFalse(encoder.matches("wrong-password", legacyHash));
    }
}
