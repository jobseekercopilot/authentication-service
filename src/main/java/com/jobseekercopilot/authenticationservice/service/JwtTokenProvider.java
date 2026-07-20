package com.jobseekercopilot.authenticationservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtTokenProvider {

    static final int MINIMUM_SIGNING_KEY_BYTES = 32;

    private final SecretKey key;
    private final long expirationMs;

    public JwtTokenProvider(
            @Value("${jwt.signing-key}") String signingKey,
            @Value("${jwt.expiration}") long expirationMs) {
        this.key = createSigningKey(signingKey);
        this.expirationMs = expirationMs;
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

    public String generateToken(String userId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .subject(userId)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    public String getUserIdFromToken(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
}
