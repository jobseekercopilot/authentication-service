package com.jobseekercopilot.authenticationservice.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtSigningKeyStartupTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
            .withUserConfiguration(JwtTestConfiguration.class)
            .withPropertyValues("jwt.expiration=3600000");

    @Test
    void applicationContextFailsSafelyWhenSigningKeyIsMissing() {
        contextRunner.run(context -> {
            Throwable startupFailure = context.getStartupFailure();
            assertNotNull(startupFailure);
            assertTrue(messageChain(startupFailure)
                    .contains("Could not resolve placeholder 'jwt.signing-key'"));
        });
    }

    @Test
    void applicationContextFailsSafelyWhenSigningKeyIsBlank() {
        contextRunner
                .withPropertyValues("jwt.signing-key=   ")
                .run(context -> assertConfigurationFailure(
                        context.getStartupFailure(),
                        "JWT signing key must be configured and must not be blank"));
    }

    @Test
    void applicationContextFailsSafelyWhenSigningKeyIsWeak() {
        String weakKey = "too-short";
        contextRunner
                .withPropertyValues("jwt.signing-key=" + weakKey)
                .run(context -> {
                    Throwable startupFailure = context.getStartupFailure();
                    assertConfigurationFailure(
                            startupFailure,
                            "JWT signing key must contain at least 32 bytes");
                    assertFalse(messageChain(startupFailure).contains(weakKey));
                });
    }

    @Test
    void applicationContextStartsWithStrongSigningKey() {
        contextRunner
                .withPropertyValues(
                        "jwt.signing-key=startup-test-signing-material-never-use-for-runtime")
                .run(context -> assertTrue(context.isRunning()));
    }

    private String messageChain(Throwable failure) {
        StringBuilder messages = new StringBuilder();
        Throwable current = failure;
        while (current != null) {
            if (current.getMessage() != null) {
                messages.append(current.getMessage()).append(' ');
            }
            current = current.getCause();
        }
        return messages.toString();
    }

    private void assertConfigurationFailure(Throwable startupFailure, String expectedMessage) {
        assertNotNull(startupFailure);
        assertTrue(messageChain(startupFailure).contains(expectedMessage));
    }

    @Configuration(proxyBeanMethods = false)
    static class JwtTestConfiguration {

        @Bean
        JwtTokenProvider jwtTokenProvider(
                @Value("${jwt.signing-key}") String signingKey,
                @Value("${jwt.expiration}") long expiration) {
            return new JwtTokenProvider(signingKey, expiration);
        }
    }
}
