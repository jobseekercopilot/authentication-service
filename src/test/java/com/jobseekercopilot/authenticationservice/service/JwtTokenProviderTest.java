package com.jobseekercopilot.authenticationservice.service;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(OutputCaptureExtension.class)
public class JwtTokenProviderTest {

    private static final String TEST_SIGNING_KEY =
            "unit-test-signing-material-never-use-for-local-runtime";
    private static final String DIFFERENT_SIGNING_KEY =
            "different-test-signing-material-never-use-for-runtime";
    private static final long ONE_HOUR_MS = 3_600_000;

    @Test
    void newlyIssuedTokenIsAccepted(CapturedOutput output) {
        JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(TEST_SIGNING_KEY, ONE_HOUR_MS);
        String userId = "user123";
        String token = jwtTokenProvider.generateToken(userId);

        assertNotNull(token);
        assertEquals(userId, jwtTokenProvider.getUserIdFromToken(token));
        assertFalse(output.getAll().contains(TEST_SIGNING_KEY));
        assertFalse(output.getAll().contains(token));
    }

    @Test
    void tokenSignedWithDifferentKeyIsRejected() {
        JwtTokenProvider currentProvider = new JwtTokenProvider(TEST_SIGNING_KEY, ONE_HOUR_MS);
        JwtTokenProvider previousProvider = new JwtTokenProvider(DIFFERENT_SIGNING_KEY, ONE_HOUR_MS);

        String tokenFromPreviousKey = previousProvider.generateToken("user123");

        assertThrows(JwtException.class,
                () -> currentProvider.getUserIdFromToken(tokenFromPreviousKey));
    }

    @Test
    void expiredTokenIsRejected() {
        SecretKey key = Keys.hmacShaKeyFor(TEST_SIGNING_KEY.getBytes(StandardCharsets.UTF_8));
        Date now = new Date();
        String expiredToken = Jwts.builder()
                .subject("user123")
                .issuedAt(new Date(now.getTime() - 2_000))
                .expiration(new Date(now.getTime() - 1_000))
                .signWith(key)
                .compact();

        JwtTokenProvider provider = new JwtTokenProvider(TEST_SIGNING_KEY, ONE_HOUR_MS);
        assertThrows(ExpiredJwtException.class, () -> provider.getUserIdFromToken(expiredToken));
    }

    @Test
    void malformedTokenIsRejected() {
        JwtTokenProvider provider = new JwtTokenProvider(TEST_SIGNING_KEY, ONE_HOUR_MS);

        assertThrows(JwtException.class, () -> provider.getUserIdFromToken("not-a-jwt"));
    }

    @Test
    void missingSigningKeyIsRejectedWithoutEchoingValue() {
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> new JwtTokenProvider(null, ONE_HOUR_MS));

        assertEquals("JWT signing key must be configured and must not be blank", exception.getMessage());
    }

    @Test
    void blankSigningKeyIsRejectedWithoutEchoingValue() {
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> new JwtTokenProvider("   ", ONE_HOUR_MS));

        assertEquals("JWT signing key must be configured and must not be blank", exception.getMessage());
    }

    @Test
    void weakSigningKeyIsRejectedWithoutEchoingValue() {
        String weakKey = "too-short";
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> new JwtTokenProvider(weakKey, ONE_HOUR_MS));

        assertEquals("JWT signing key must contain at least 32 bytes", exception.getMessage());
        assertFalse(exception.getMessage().contains(weakKey));
    }
}
