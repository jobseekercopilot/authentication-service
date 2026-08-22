package com.jobseekercopilot.authenticationservice.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.jobseekercopilot.authenticationservice.exception.RefreshTokenException;
import com.jobseekercopilot.authenticationservice.model.AuthenticationSession;
import com.jobseekercopilot.authenticationservice.model.RefreshToken;
import com.jobseekercopilot.authenticationservice.repository.AuthenticationSessionRepository;
import com.jobseekercopilot.authenticationservice.repository.RefreshTokenRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SessionTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-07-21T12:00:00Z");

    @Mock
    private AuthenticationSessionRepository sessionRepository;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private JwtTokenProvider jwtTokenProvider;

    private SessionTokenService service;

    @BeforeEach
    void setUp() {
        service = new SessionTokenService(sessionRepository, refreshTokenRepository,
                jwtTokenProvider, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofDays(7));
    }

    @Test
    void issueStoresOnlyAHashAndUsesAnAbsoluteSessionLifetime() {
        when(jwtTokenProvider.generateAccessToken(any(), any())).thenReturn("access-token");
        when(jwtTokenProvider.getExpirationSeconds()).thenReturn(900L);
        var response = service.issue("user-123");

        ArgumentCaptor<AuthenticationSession> session = ArgumentCaptor.forClass(AuthenticationSession.class);
        ArgumentCaptor<RefreshToken> refresh = ArgumentCaptor.forClass(RefreshToken.class);
        verify(sessionRepository).save(session.capture());
        verify(refreshTokenRepository).save(refresh.capture());
        assertEquals(NOW.plus(Duration.ofDays(7)), session.getValue().getExpiresAt());
        assertEquals(64, refresh.getValue().getTokenHash().length());
        assertNotEquals(response.getRefreshToken(), refresh.getValue().getTokenHash());
        assertFalse(refresh.getValue().getTokenHash().contains(response.getRefreshToken()));
    }

    @Test
    void consumedRefreshTokenRevokesItsSessionAsReplay() {
        AuthenticationSession session = new AuthenticationSession(
                "session-123", "user-123", NOW.minusSeconds(10), NOW.plusSeconds(100), null);
        RefreshToken consumed = new RefreshToken(
                "refresh-123", session.getId(), SessionTokenService.hash("old-refresh"),
                NOW.minusSeconds(10), NOW.plusSeconds(100), NOW.minusSeconds(1));
        when(refreshTokenRepository.findByTokenHashForUpdate(SessionTokenService.hash("old-refresh")))
                .thenReturn(Optional.of(consumed));
        when(sessionRepository.findById("session-123")).thenReturn(Optional.of(session));

        RefreshTokenException failure = assertThrows(RefreshTokenException.class,
                () -> service.rotate("old-refresh"));

        assertEquals("REFRESH_TOKEN_REUSED", failure.getCode());
        assertEquals(NOW, session.getRevokedAt());
        verify(sessionRepository).save(session);
    }
}
