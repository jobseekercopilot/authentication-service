package com.jobseekercopilot.authenticationservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;
    private final String secret = "00000000000000000000000000000000";
    private final long expiration = 3600000; // 1 hour

    @BeforeEach
    void setUp() {
        jwtTokenProvider = new JwtTokenProvider(secret, expiration);
    }

    @Test
    void generateToken_ShouldReturnValidToken() {
        String userId = "user123";
        String token = jwtTokenProvider.generateToken(userId);

        assertNotNull(token);

        // Verify the token content
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertEquals(userId, claims.getSubject());
        assertTrue(claims.getExpiration().after(new Date()));
    }
}
