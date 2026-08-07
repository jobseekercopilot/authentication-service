package com.jobseekercopilot.authenticationservice.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.jobseekercopilot.authenticationservice.model.AccountDeletionOperation;
import com.jobseekercopilot.authenticationservice.model.AccountDeletionStatus;
import com.jobseekercopilot.authenticationservice.model.User;
import com.jobseekercopilot.authenticationservice.repository.AccountDeletionOperationRepository;
import com.jobseekercopilot.authenticationservice.repository.AuthenticationSessionRepository;
import com.jobseekercopilot.authenticationservice.repository.PasswordResetTokenRepository;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AccountDeletionTransactionTest {

    private static final Instant NOW = Instant.parse("2026-08-07T08:00:00Z");

    @Mock
    private AccountDeletionOperationRepository operationRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private AuthenticationSessionRepository sessionRepository;
    @Mock
    private PasswordResetTokenRepository resetTokenRepository;
    @Mock
    private PasswordEncoder passwordEncoder;

    private AccountDeletionTransaction transaction;

    @BeforeEach
    void setUp() {
        transaction = new AccountDeletionTransaction(
                operationRepository,
                userRepository,
                sessionRepository,
                resetTokenRepository,
                passwordEncoder,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void startingDeletionScrubsCredentialsRevokesSessionsAndStoresOnlyAKeyHash() {
        User user = new User(
                "user-123",
                "Alice Example",
                "alice@example.test",
                "alice@example.test",
                "old-password-hash",
                LocalDateTime.ofInstant(NOW.minusSeconds(3600), ZoneOffset.UTC),
                true);
        when(operationRepository.findByUserIdAndIdempotencyKeyHash(any(), any()))
                .thenReturn(Optional.empty());
        when(userRepository.findByIdForUpdate("user-123"))
                .thenReturn(Optional.of(user));
        when(passwordEncoder.encode(any())).thenReturn("deleted-password-hash");

        AccountDeletionOperation operation = transaction.start(
                "user-123", "delete-request-0001");

        assertEquals(AccountDeletionStatus.PENDING, operation.getStatus());
        assertEquals(64, operation.getIdempotencyKeyHash().length());
        assertNotEquals("delete-request-0001", operation.getIdempotencyKeyHash());
        assertFalse(user.isActive());
        assertEquals("Deleted account", user.getName());
        assertEquals("deleted+user-123@invalid.jobseekercopilot", user.getEmail());
        assertEquals("deleted-password-hash", user.getPasswordHash());
        verify(resetTokenRepository).deleteByUserId("user-123");
        verify(sessionRepository).deleteByUserId("user-123");
        verify(operationRepository).flush();
        ArgumentCaptor<AccountDeletionOperation> stored =
                ArgumentCaptor.forClass(AccountDeletionOperation.class);
        verify(operationRepository).save(stored.capture());
        assertEquals(operation.getId(), stored.getValue().getId());
    }
}
