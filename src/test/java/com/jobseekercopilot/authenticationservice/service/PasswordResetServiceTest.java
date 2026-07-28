package com.jobseekercopilot.authenticationservice.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.jobseekercopilot.authenticationservice.identity.EmailIdentityCanonicalizer;
import com.jobseekercopilot.authenticationservice.model.PasswordResetRequest;
import com.jobseekercopilot.authenticationservice.model.PasswordResetToken;
import com.jobseekercopilot.authenticationservice.model.User;
import com.jobseekercopilot.authenticationservice.repository.AuthenticationSessionRepository;
import com.jobseekercopilot.authenticationservice.repository.PasswordResetTokenRepository;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;

class PasswordResetServiceTest {

    private static final Instant NOW = Instant.parse("2026-07-28T12:00:00Z");
    private static final String EMAIL = "person@example.test";

    private UserRepository users;
    private PasswordResetTokenRepository tokens;
    private ApplicationEventPublisher events;
    private PasswordResetService service;
    private User user;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        tokens = mock(PasswordResetTokenRepository.class);
        events = mock(ApplicationEventPublisher.class);
        user = new User(
                "account-123", "Reset User", EMAIL, EMAIL, "encoded",
                LocalDateTime.ofInstant(NOW, ZoneOffset.UTC), true);
        when(users.findByCanonicalEmailForUpdate(EMAIL)).thenReturn(Optional.of(user));
        service = new PasswordResetService(
                users,
                tokens,
                mock(AuthenticationSessionRepository.class),
                mock(PasswordEncoder.class),
                mock(PasswordPolicy.class),
                new EmailIdentityCanonicalizer(),
                events,
                Clock.fixed(NOW, ZoneOffset.UTC),
                Duration.ofMinutes(30),
                Duration.ofSeconds(60));
    }

    @Test
    void ignoresARepeatedRequestInsideTheSixtySecondAccountCooldown() {
        PasswordResetToken existing = tokenCreatedAt(NOW.minusSeconds(59));
        when(tokens.findTopByUserIdOrderByCreatedAtDesc(user.getId()))
                .thenReturn(Optional.of(existing));

        service.requestReset(new PasswordResetRequest(EMAIL));

        verify(tokens, never()).invalidateUnusedForUser(any(), any());
        verify(tokens, never()).save(any());
        verify(events, never()).publishEvent(any());
    }

    @Test
    void issuesANewDigestAndInvalidatesEarlierTokensWhenCooldownHasElapsed() {
        PasswordResetToken existing = tokenCreatedAt(NOW.minusSeconds(60));
        when(tokens.findTopByUserIdOrderByCreatedAtDesc(user.getId()))
                .thenReturn(Optional.of(existing));

        service.requestReset(new PasswordResetRequest("  PERSON@example.test  "));

        verify(tokens).invalidateUnusedForUser(user.getId(), NOW);
        ArgumentCaptor<PasswordResetToken> stored =
                ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokens).save(stored.capture());
        assertEquals(64, stored.getValue().getTokenHash().length());
        ArgumentCaptor<Object> event = ArgumentCaptor.forClass(Object.class);
        verify(events).publishEvent(event.capture());
        PasswordResetEmailRequested requested = (PasswordResetEmailRequested) event.getValue();
        assertNotEquals(requested.rawToken(), stored.getValue().getTokenHash());
        assertEquals(NOW.plus(Duration.ofMinutes(30)), requested.expiresAt());
        verify(tokens, never()).invalidateUnusedExcept(any(), any(), any());
    }

    @Test
    void unknownAccountReturnsWithoutCreatingTokenOrEmailEvent() {
        when(users.findByCanonicalEmailForUpdate("unknown@example.test"))
                .thenReturn(Optional.empty());

        service.requestReset(new PasswordResetRequest("unknown@example.test"));

        verify(tokens, never()).save(any());
        verify(events, never()).publishEvent(any());
    }

    private PasswordResetToken tokenCreatedAt(Instant createdAt) {
        return new PasswordResetToken(
                "token-123", user.getId(), "0".repeat(64), createdAt,
                createdAt.plus(Duration.ofMinutes(30)), null, null);
    }
}
