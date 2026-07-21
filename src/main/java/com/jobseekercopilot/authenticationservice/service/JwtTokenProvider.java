package com.jobseekercopilot.authenticationservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Date;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

    static final int MINIMUM_SIGNING_KEY_BYTES = 32;
    static final long MAXIMUM_ACCESS_TOKEN_LIFETIME_MS = 3_600_000;
    private static final String ACCESS_TOKEN_TYPE = "access";
    private static final String SESSION_ID_CLAIM = "sid";
    private static final String TOKEN_TYPE_CLAIM = "token_type";

    private final SecretKey key;
    private final long expirationMs;
    private final String issuer;
    private final String audience;
    private final String keyId;
    private final long clockSkewSeconds;
    private final Clock clock;

    @Autowired
    public JwtTokenProvider(
            @Value("${jwt.signing-key}") String signingKey,
            @Value("${jwt.expiration:900000}") long expirationMs,
            @Value("${jwt.issuer:job-seeker-copilot-authentication}") String issuer,
            @Value("${jwt.audience:job-seeker-copilot-services}") String audience,
            @Value("${jwt.key-id:primary}") String keyId,
            @Value("${jwt.clock-skew-seconds:30}") long clockSkewSeconds,
            Clock clock) {
        this.key = createSigningKey(signingKey);
        if (expirationMs <= 0 || expirationMs > MAXIMUM_ACCESS_TOKEN_LIFETIME_MS) {
            throw new IllegalStateException("JWT access-token lifetime must be between 1ms and 1 hour");
        }
        if (issuer == null || issuer.isBlank() || audience == null || audience.isBlank()
                || keyId == null || keyId.isBlank()) {
            throw new IllegalStateException("JWT issuer, audience and key ID must be configured");
        }
        if (clockSkewSeconds < 0 || clockSkewSeconds > 300) {
            throw new IllegalStateException("JWT clock skew must be between 0 and 300 seconds");
        }
        this.expirationMs = expirationMs;
        this.issuer = issuer;
        this.audience = audience;
        this.keyId = keyId;
        this.clockSkewSeconds = clockSkewSeconds;
        this.clock = clock;
    }

    JwtTokenProvider(String signingKey, long expirationMs) {
        this(signingKey, expirationMs, "test-issuer", "test-audience", "test-key", 0, Clock.systemUTC());
    }

    private static SecretKey createSigningKey(String signingKey) {
        if (signingKey == null || signingKey.isBlank()) {
            throw new IllegalStateException("JWT signing key must be configured and must not be blank");
        }
        byte[] keyMaterial = signingKey.getBytes(StandardCharsets.UTF_8);
        if (keyMaterial.length < MINIMUM_SIGNING_KEY_BYTES) {
            throw new IllegalStateException(
                    "JWT signing key must contain at least " + MINIMUM_SIGNING_KEY_BYTES + " bytes");
        }
        return Keys.hmacShaKeyFor(keyMaterial);
    }

    public String generateAccessToken(String userId, String sessionId) {
        Date now = Date.from(clock.instant());
        return Jwts.builder()
                .header().keyId(keyId).and()
                .issuer(issuer)
                .audience().add(audience).and()
                .subject(userId)
                .id(UUID.randomUUID().toString())
                .claim(SESSION_ID_CLAIM, sessionId)
                .claim(TOKEN_TYPE_CLAIM, ACCESS_TOKEN_TYPE)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + expirationMs))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public AccessTokenClaims parseAccessToken(String token) {
        Jws<Claims> parsed = Jwts.parser()
                .verifyWith(key)
                .requireIssuer(issuer)
                .requireAudience(audience)
                .clockSkewSeconds(clockSkewSeconds)
                .clock(() -> Date.from(clock.instant()))
                .build()
                .parseSignedClaims(token);
        Claims claims = parsed.getPayload();
        if (!Jwts.SIG.HS256.getId().equals(parsed.getHeader().getAlgorithm())
                || !keyId.equals(parsed.getHeader().getKeyId())
                || !ACCESS_TOKEN_TYPE.equals(claims.get(TOKEN_TYPE_CLAIM, String.class))
                || claims.getId() == null || claims.getId().isBlank()) {
            throw new io.jsonwebtoken.JwtException("Access token metadata is invalid");
        }
        String userId = claims.getSubject();
        String sessionId = claims.get(SESSION_ID_CLAIM, String.class);
        if (userId == null || userId.isBlank() || sessionId == null || sessionId.isBlank()) {
            throw new io.jsonwebtoken.JwtException("Access token claims are invalid");
        }
        return new AccessTokenClaims(userId, sessionId);
    }

    public long getExpirationSeconds() {
        return expirationMs / 1000;
    }

    public String generateToken(String userId) {
        return generateAccessToken(userId, "legacy-test-session");
    }

    public String getUserIdFromToken(String token) {
        return parseAccessToken(token).userId();
    }
}
