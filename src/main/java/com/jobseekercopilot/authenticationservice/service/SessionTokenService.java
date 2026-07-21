package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.RefreshTokenException;
import com.jobseekercopilot.authenticationservice.exception.TokenValidationException;
import com.jobseekercopilot.authenticationservice.model.AuthenticationSession;
import com.jobseekercopilot.authenticationservice.model.LoginResponse;
import com.jobseekercopilot.authenticationservice.model.RefreshToken;
import com.jobseekercopilot.authenticationservice.repository.AuthenticationSessionRepository;
import com.jobseekercopilot.authenticationservice.repository.RefreshTokenRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SessionTokenService {

    private static final int REFRESH_TOKEN_BYTES = 32;

    private final AuthenticationSessionRepository sessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final Clock clock;
    private final Duration refreshLifetime;
    private final SecureRandom secureRandom = new SecureRandom();

    public SessionTokenService(
            AuthenticationSessionRepository sessionRepository,
            RefreshTokenRepository refreshTokenRepository,
            JwtTokenProvider jwtTokenProvider,
            Clock clock,
            @Value("${auth.session.refresh-lifetime:7d}") Duration refreshLifetime) {
        if (refreshLifetime == null || refreshLifetime.isNegative() || refreshLifetime.isZero()) {
            throw new IllegalStateException("Refresh-token lifetime must be positive");
        }
        this.sessionRepository = sessionRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.clock = clock;
        this.refreshLifetime = refreshLifetime;
    }

    @Transactional
    public LoginResponse issue(String userId) {
        Instant now = clock.instant();
        AuthenticationSession session = new AuthenticationSession(
                UUID.randomUUID().toString(), userId, now, now.plus(refreshLifetime), null);
        sessionRepository.save(session);
        return issueTokens(session, now);
    }

    @Transactional(noRollbackFor = RefreshTokenException.class)
    public LoginResponse rotate(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw RefreshTokenException.invalid();
        }
        RefreshToken current = refreshTokenRepository.findByTokenHashForUpdate(hash(rawRefreshToken))
                .orElseThrow(RefreshTokenException::invalid);
        AuthenticationSession session = sessionRepository.findById(current.getSessionId())
                .orElseThrow(RefreshTokenException::invalid);
        Instant now = clock.instant();

        if (current.getUsedAt() != null) {
            revoke(session, now);
            throw RefreshTokenException.reused();
        }
        if (session.getRevokedAt() != null || !now.isBefore(session.getExpiresAt())
                || !now.isBefore(current.getExpiresAt())) {
            revoke(session, now);
            throw RefreshTokenException.invalid();
        }

        current.setUsedAt(now);
        refreshTokenRepository.save(current);
        return issueTokens(session, now);
    }

    @Transactional(readOnly = true)
    public void validate(AccessTokenClaims claims) {
        AuthenticationSession session = sessionRepository.findById(claims.sessionId())
                .orElseThrow(TokenValidationException::invalid);
        if (!session.getUserId().equals(claims.userId())
                || session.getRevokedAt() != null
                || !clock.instant().isBefore(session.getExpiresAt())) {
            throw TokenValidationException.invalid();
        }
    }

    @Transactional
    public void revoke(AccessTokenClaims claims) {
        sessionRepository.findById(claims.sessionId()).ifPresent(session -> {
            if (session.getUserId().equals(claims.userId()) && session.getRevokedAt() == null) {
                revoke(session, clock.instant());
            }
        });
    }

    private LoginResponse issueTokens(AuthenticationSession session, Instant now) {
        String rawRefreshToken = randomToken();
        refreshTokenRepository.save(new RefreshToken(
                UUID.randomUUID().toString(),
                session.getId(),
                hash(rawRefreshToken),
                now,
                session.getExpiresAt(),
                null));
        String accessToken = jwtTokenProvider.generateAccessToken(session.getUserId(), session.getId());
        return new LoginResponse(accessToken, rawRefreshToken, "Bearer", jwtTokenProvider.getExpirationSeconds());
    }

    private void revoke(AuthenticationSession session, Instant now) {
        if (session.getRevokedAt() == null) {
            session.setRevokedAt(now);
            sessionRepository.save(session);
        }
    }

    private String randomToken() {
        byte[] bytes = new byte[REFRESH_TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
