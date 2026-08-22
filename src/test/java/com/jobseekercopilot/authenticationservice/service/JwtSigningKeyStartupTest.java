package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.TestJwtKeys;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.junit.jupiter.api.Assertions.*;

class JwtSigningKeyStartupTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
            .withUserConfiguration(JwtTestConfiguration.class)
            .withPropertyValues("jwt.expiration=3600000", "jwt.previous-public-keys=");

    @Test
    void applicationContextFailsSafelyWhenKeysAreMissing() {
        contextRunner.run(context -> {
            assertNotNull(context.getStartupFailure());
            assertTrue(messages(context.getStartupFailure()).contains("jwt.private-key-base64"));
        });
    }

    @Test
    void applicationContextFailsSafelyForMalformedOrMismatchedKeysWithoutEchoingMaterial() {
        String privateKey = TestJwtKeys.privateKey(TestJwtKeys.ACTIVE);
        contextRunner.withPropertyValues("jwt.private-key-base64=malformed", "jwt.public-key-base64=malformed")
                .run(context -> assertConfigurationFailure(context.getStartupFailure()));
        contextRunner.withPropertyValues("jwt.private-key-base64=" + privateKey,
                        "jwt.public-key-base64=" + TestJwtKeys.publicKey(TestJwtKeys.DIFFERENT))
                .run(context -> {
                    assertConfigurationFailure(context.getStartupFailure());
                    assertFalse(messages(context.getStartupFailure()).contains(privateKey));
                });
    }

    @Test
    void applicationContextFailsForWeakRsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair weak = generator.generateKeyPair();
        contextRunner.withPropertyValues("jwt.private-key-base64=" + TestJwtKeys.privateKey(weak),
                        "jwt.public-key-base64=" + TestJwtKeys.publicKey(weak))
                .run(context -> assertConfigurationFailure(context.getStartupFailure()));
    }

    @Test
    void applicationContextStartsWithMatchingStrongRsaKeys() {
        contextRunner.withPropertyValues(
                        "jwt.private-key-base64=" + TestJwtKeys.privateKey(TestJwtKeys.ACTIVE),
                        "jwt.public-key-base64=" + TestJwtKeys.publicKey(TestJwtKeys.ACTIVE))
                .run(context -> assertTrue(context.isRunning()));
    }

    private static void assertConfigurationFailure(Throwable failure) {
        assertNotNull(failure);
        assertTrue(messages(failure).contains("JWT RSA key configuration is missing or invalid"));
    }

    private static String messages(Throwable failure) {
        StringBuilder result = new StringBuilder();
        for (Throwable current = failure; current != null; current = current.getCause()) {
            if (current.getMessage() != null) result.append(current.getMessage()).append(' ');
        }
        return result.toString();
    }

    @Configuration(proxyBeanMethods = false)
    static class JwtTestConfiguration {
        @Bean
        JwtTokenProvider jwtTokenProvider(
                @Value("${jwt.private-key-base64}") String privateKey,
                @Value("${jwt.public-key-base64}") String publicKey,
                @Value("${jwt.previous-public-keys}") String previousKeys,
                @Value("${jwt.expiration}") long expiration) {
            return new JwtTokenProvider(privateKey, publicKey, previousKeys, expiration,
                    "test-issuer", "test-audience", "test-key", 0, java.time.Clock.systemUTC());
        }
    }
}
