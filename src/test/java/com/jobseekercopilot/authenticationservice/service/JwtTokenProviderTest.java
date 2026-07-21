package com.jobseekercopilot.authenticationservice.service;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
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
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

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

    @Test
    void issuedAccessTokenHasConstrainedMetadataAndClaims() {
        Clock clock = Clock.fixed(Instant.parse("2026-07-21T12:00:00Z"), ZoneOffset.UTC);
        JwtTokenProvider provider = new JwtTokenProvider(
                TEST_SIGNING_KEY, 900_000, "expected-issuer", "expected-audience", "key-2026-01", 30, clock);

        String token = provider.generateAccessToken("user-123", "session-123");
        SecretKey key = Keys.hmacShaKeyFor(TEST_SIGNING_KEY.getBytes(StandardCharsets.UTF_8));
        Jws<Claims> parsed = Jwts.parser().verifyWith(key)
                .clock(() -> Date.from(clock.instant()))
                .build().parseSignedClaims(token);

        assertEquals("HS256", parsed.getHeader().getAlgorithm());
        assertEquals("key-2026-01", parsed.getHeader().getKeyId());
        assertEquals("expected-issuer", parsed.getPayload().getIssuer());
        assertTrue(parsed.getPayload().getAudience().contains("expected-audience"));
        assertEquals("user-123", parsed.getPayload().getSubject());
        assertEquals("session-123", parsed.getPayload().get("sid", String.class));
        assertEquals("access", parsed.getPayload().get("token_type", String.class));
        assertNotNull(parsed.getPayload().getId());
    }

    @Test
    void wrongIssuerAudienceOrAlgorithmIsRejected() {
        Clock clock = Clock.fixed(Instant.parse("2026-07-21T12:00:00Z"), ZoneOffset.UTC);
        JwtTokenProvider provider = new JwtTokenProvider(
                TEST_SIGNING_KEY, 900_000, "expected-issuer", "expected-audience", "test-key", 30, clock);

        assertThrows(JwtException.class, () -> provider.parseAccessToken(
                constrainedToken(clock, "wrong-issuer", "expected-audience", Jwts.SIG.HS256)));
        assertThrows(JwtException.class, () -> provider.parseAccessToken(
                constrainedToken(clock, "expected-issuer", "wrong-audience", Jwts.SIG.HS256)));
        assertThrows(JwtException.class, () -> provider.parseAccessToken(
                constrainedToken(clock, "expected-issuer", "expected-audience", Jwts.SIG.HS384)));
    }

    @Test
    void configuredClockSkewIsAcceptedButNotExceeded() {
        Instant now = Instant.parse("2026-07-21T12:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        JwtTokenProvider provider = new JwtTokenProvider(
                TEST_SIGNING_KEY, 900_000, "expected-issuer", "expected-audience", "test-key", 30, clock);

        String withinSkew = constrainedToken(clock, "expected-issuer", "expected-audience",
                Jwts.SIG.HS256, now.minusSeconds(20));
        String beyondSkew = constrainedToken(clock, "expected-issuer", "expected-audience",
                Jwts.SIG.HS256, now.minusSeconds(31));

        assertEquals("user-123", provider.parseAccessToken(withinSkew).userId());
        assertThrows(ExpiredJwtException.class, () -> provider.parseAccessToken(beyondSkew));
    }

    private String constrainedToken(
            Clock clock, String issuer, String audience,
            io.jsonwebtoken.security.MacAlgorithm algorithm) {
        return constrainedToken(clock, issuer, audience, algorithm, clock.instant().plusSeconds(300));
    }

    private String constrainedToken(
            Clock clock, String issuer, String audience,
            io.jsonwebtoken.security.MacAlgorithm algorithm, Instant expiration) {
        SecretKey key = Keys.hmacShaKeyFor(TEST_SIGNING_KEY.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .header().keyId("test-key").and()
                .issuer(issuer)
                .audience().add(audience).and()
                .subject("user-123")
                .id("token-id")
                .claim("sid", "session-123")
                .claim("token_type", "access")
                .issuedAt(Date.from(clock.instant().minusSeconds(60)))
                .expiration(Date.from(expiration))
                .signWith(key, algorithm)
                .compact();
    }
}
