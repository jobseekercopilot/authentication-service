package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.TestJwtKeys;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenProviderTest {

    private static final long ONE_HOUR_MS = 3_600_000;
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-07-21T12:00:00Z"), ZoneOffset.UTC);

    @Test
    void newlyIssuedRs256TokenIsAcceptedAndPublishesOnlyPublicMaterial() {
        JwtTokenProvider provider = provider(TestJwtKeys.ACTIVE, Map.of(), "active");
        String token = provider.generateAccessToken("user123", "session123");

        assertEquals("user123", provider.parseAccessToken(token).userId());
        var parsed = Jwts.parser().verifyWith(TestJwtKeys.ACTIVE.getPublic())
                .clock(() -> Date.from(CLOCK.instant())).build().parseSignedClaims(token);
        assertEquals("RS256", parsed.getHeader().getAlgorithm());
        assertEquals("active", parsed.getHeader().getKeyId());
        assertEquals("session123", parsed.getPayload().get("sid"));
        assertEquals("access", parsed.getPayload().get("token_type"));

        Map<String, String> jwk = provider.getJsonWebKeys().get(0);
        assertEquals(Map.of("kty", "RSA", "use", "sig", "alg", "RS256", "kid", "active",
                "n", jwk.get("n"), "e", jwk.get("e")), jwk);
        assertFalse(jwk.containsKey("d"));
        assertFalse(jwk.toString().contains(TestJwtKeys.privateKey(TestJwtKeys.ACTIVE)));
    }

    @Test
    void accountLifecycleTokenIsShortLivedAndBoundToOneOperation() {
        JwtTokenProvider provider = provider(TestJwtKeys.ACTIVE, Map.of(), "active");

        String token = provider.generateAccountLifecycleToken("user123", "operation123");
        var parsed = Jwts.parser()
                .verifyWith(TestJwtKeys.ACTIVE.getPublic())
                .clock(() -> Date.from(CLOCK.instant()))
                .build()
                .parseSignedClaims(token);

        assertEquals("user123", parsed.getPayload().getSubject());
        assertEquals("account_lifecycle", parsed.getPayload().get("token_type"));
        assertEquals("operation123", parsed.getPayload().get("operation_id"));
        assertEquals(
                CLOCK.instant().plusSeconds(300),
                parsed.getPayload().getExpiration().toInstant());
        assertThrows(JwtException.class, () -> provider.parseAccessToken(token));
    }

    @Test
    void previousPublicKeyRemainsValidDuringRotationAndIsPublished() {
        JwtTokenProvider oldProvider = provider(TestJwtKeys.PREVIOUS, Map.of(), "previous");
        JwtTokenProvider currentProvider = provider(
                TestJwtKeys.ACTIVE, Map.of("previous", TestJwtKeys.PREVIOUS.getPublic()), "active");

        assertEquals("user123", currentProvider.parseAccessToken(oldProvider.generateToken("user123")).userId());
        assertEquals(2, currentProvider.getJsonWebKeys().size());
    }

    @Test
    void unknownKeyWrongAlgorithmMalformedAndExpiredTokensAreRejected() throws Exception {
        JwtTokenProvider provider = provider(TestJwtKeys.ACTIVE, Map.of(), "active");
        JwtTokenProvider other = provider(TestJwtKeys.DIFFERENT, Map.of(), "different");
        assertThrows(JwtException.class, () -> provider.parseAccessToken(other.generateToken("user123")));
        String forgedKnownKeyId = constrainedToken(TestJwtKeys.DIFFERENT, "active",
                "expected-issuer", "expected-audience", CLOCK.instant().plusSeconds(60));
        assertThrows(JwtException.class, () -> provider.parseAccessToken(forgedKnownKeyId));
        assertThrows(JwtException.class, () -> provider.parseAccessToken("not-a-jwt"));

        String expired = constrainedToken(TestJwtKeys.ACTIVE, "active", "expected-issuer",
                "expected-audience", CLOCK.instant().minusSeconds(31));
        assertThrows(ExpiredJwtException.class, () -> provider.parseAccessToken(expired));

        var hmac = io.jsonwebtoken.security.Keys.hmacShaKeyFor(new byte[32]);
        String wrongAlgorithm = Jwts.builder().header().keyId("active").and().subject("user")
                .expiration(Date.from(CLOCK.instant().plusSeconds(60))).signWith(hmac).compact();
        assertThrows(JwtException.class, () -> provider.parseAccessToken(wrongAlgorithm));
    }

    @Test
    void issuerAudienceAndClockSkewAreEnforced() {
        JwtTokenProvider provider = provider(TestJwtKeys.ACTIVE, Map.of(), "active");
        assertThrows(JwtException.class, () -> provider.parseAccessToken(constrainedToken(
                TestJwtKeys.ACTIVE, "active", "wrong", "expected-audience", CLOCK.instant().plusSeconds(60))));
        assertThrows(JwtException.class, () -> provider.parseAccessToken(constrainedToken(
                TestJwtKeys.ACTIVE, "active", "expected-issuer", "wrong", CLOCK.instant().plusSeconds(60))));
        assertEquals("user-123", provider.parseAccessToken(constrainedToken(
                TestJwtKeys.ACTIVE, "active", "expected-issuer", "expected-audience",
                CLOCK.instant().minusSeconds(20))).userId());
        assertThrows(ExpiredJwtException.class, () -> provider.parseAccessToken(constrainedToken(
                TestJwtKeys.ACTIVE, "active", "expected-issuer", "expected-audience",
                CLOCK.instant().minusSeconds(31))));
    }

    @Test
    void missingMalformedWeakMismatchedAndDuplicateKeyConfigurationFailsSafely() throws Exception {
        assertConfigFailure(() -> new JwtTokenProvider(null, "bad", "", ONE_HOUR_MS,
                "issuer", "audience", "active", 0, CLOCK));
        assertConfigFailure(() -> new JwtTokenProvider("bad", "bad", "", ONE_HOUR_MS,
                "issuer", "audience", "active", 0, CLOCK));
        assertConfigFailure(() -> new JwtTokenProvider(TestJwtKeys.privateKey(TestJwtKeys.ACTIVE),
                TestJwtKeys.publicKey(TestJwtKeys.DIFFERENT), "", ONE_HOUR_MS,
                "issuer", "audience", "active", 0, CLOCK));

        KeyPairGenerator weakGenerator = KeyPairGenerator.getInstance("RSA");
        weakGenerator.initialize(1024);
        KeyPair weak = weakGenerator.generateKeyPair();
        assertConfigFailure(() -> new JwtTokenProvider(TestJwtKeys.privateKey(weak),
                TestJwtKeys.publicKey(weak), "", ONE_HOUR_MS,
                "issuer", "audience", "active", 0, CLOCK));
        IllegalStateException duplicate = assertThrows(IllegalStateException.class,
                () -> new JwtTokenProvider(TestJwtKeys.privateKey(TestJwtKeys.ACTIVE),
                TestJwtKeys.publicKey(TestJwtKeys.ACTIVE),
                "active=" + TestJwtKeys.publicKey(TestJwtKeys.PREVIOUS), ONE_HOUR_MS,
                "issuer", "audience", "active", 0, CLOCK));
        assertEquals("JWT issuer, audience and unique key IDs must be configured", duplicate.getMessage());
    }

    private static JwtTokenProvider provider(KeyPair pair, Map<String, PublicKey> previous, String kid) {
        return new JwtTokenProvider(pair.getPrivate(), pair.getPublic(), previous, 900_000,
                "expected-issuer", "expected-audience", kid, 30, CLOCK);
    }

    private static String constrainedToken(
            KeyPair pair, String kid, String issuer, String audience, Instant expiration) {
        return Jwts.builder().header().keyId(kid).and().issuer(issuer).audience().add(audience).and()
                .subject("user-123").id("token-id").claim("sid", "session-123")
                .claim("token_type", "access").issuedAt(Date.from(CLOCK.instant().minusSeconds(60)))
                .expiration(Date.from(expiration)).signWith(pair.getPrivate(), Jwts.SIG.RS256).compact();
    }

    private static void assertConfigFailure(org.junit.jupiter.api.function.Executable executable) {
        IllegalStateException exception = assertThrows(IllegalStateException.class, executable);
        assertEquals("JWT RSA key configuration is missing or invalid", exception.getMessage());
    }
}
