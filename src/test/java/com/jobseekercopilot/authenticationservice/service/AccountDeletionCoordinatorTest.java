package com.jobseekercopilot.authenticationservice.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.jobseekercopilot.authenticationservice.model.AccountDeletionOperation;
import com.jobseekercopilot.authenticationservice.model.AccountDeletionStatus;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class AccountDeletionCoordinatorTest {

    private static final Instant NOW = Instant.parse("2026-08-07T08:00:00Z");

    @Mock
    private AccountDeletionTransaction transaction;
    @Mock
    private AccountLifecycleDownstreamClient downstream;
    @Mock
    private JwtTokenProvider tokenProvider;

    private AccountDeletionCoordinator coordinator;

    @BeforeEach
    void setUp() {
        coordinator = new AccountDeletionCoordinator(transaction, downstream, tokenProvider);
        ReflectionTestUtils.setField(
                coordinator, "completedOperationRetention", Duration.ofDays(365));
        when(tokenProvider.generateAccountLifecycleToken("user-123", "operation-123"))
                .thenReturn("lifecycle-token");
    }

    @Test
    void completesInDependencyOrderAndRetainsAContentFreeJournal() {
        AccountDeletionOperation operation = operation();
        when(transaction.get(operation.getId())).thenReturn(operation);
        when(transaction.markStep(any(), any())).thenAnswer(invocation -> {
            AccountDeletionTransaction.Step step = invocation.getArgument(1);
            if (step == AccountDeletionTransaction.Step.PAYMENT_SERVICE) {
                operation.setPaymentServiceCompletedAt(NOW);
            } else if (step == AccountDeletionTransaction.Step.DOCUMENT_STORE) {
                operation.setDocumentStoreCompletedAt(NOW);
            } else if (step == AccountDeletionTransaction.Step.APPLICATION_TRACKER) {
                operation.setApplicationTrackerCompletedAt(NOW);
            } else {
                operation.setUserProfileCompletedAt(NOW);
            }
            return operation;
        });
        AccountDeletionOperation completed = operation();
        completed.setStatus(AccountDeletionStatus.COMPLETED);
        when(transaction.complete("operation-123", Duration.ofDays(365)))
                .thenReturn(completed);

        assertEquals(AccountDeletionStatus.COMPLETED,
                coordinator.process("operation-123").getStatus());

        InOrder order = inOrder(downstream, transaction);
        order.verify(downstream).revokePaymentAccess("user-123");
        order.verify(transaction).markStep(
                "operation-123", AccountDeletionTransaction.Step.PAYMENT_SERVICE);
        order.verify(downstream).recoverablyDeleteDocuments("lifecycle-token");
        order.verify(transaction).markStep(
                "operation-123", AccountDeletionTransaction.Step.DOCUMENT_STORE);
        order.verify(downstream).eraseApplications("lifecycle-token");
        order.verify(transaction).markStep(
                "operation-123", AccountDeletionTransaction.Step.APPLICATION_TRACKER);
        order.verify(downstream).eraseProfile("lifecycle-token");
        order.verify(transaction).markStep(
                "operation-123", AccountDeletionTransaction.Step.USER_PROFILE);
        order.verify(transaction).complete("operation-123", Duration.ofDays(365));
    }

    @Test
    void recordsRetryAndDoesNotRepeatCompletedSteps() {
        AccountDeletionOperation operation = operation();
        operation.setPaymentServiceCompletedAt(NOW);
        operation.setDocumentStoreCompletedAt(NOW);
        when(transaction.get(operation.getId())).thenReturn(operation);
        org.mockito.Mockito.doThrow(new AccountLifecycleDownstreamException(
                        "TRACKER_UNAVAILABLE", new IllegalStateException("offline")))
                .when(downstream).eraseApplications("lifecycle-token");
        operation.setStatus(AccountDeletionStatus.RETRY_REQUIRED);
        when(transaction.markFailure("operation-123", "TRACKER_UNAVAILABLE"))
                .thenReturn(operation);

        assertEquals(AccountDeletionStatus.RETRY_REQUIRED,
                coordinator.process("operation-123").getStatus());

        verify(downstream, never()).recoverablyDeleteDocuments(any());
        verify(downstream, never()).revokePaymentAccess(any());
        verify(downstream).eraseApplications("lifecycle-token");
        verify(downstream, never()).eraseProfile(any());
        verify(transaction).markFailure("operation-123", "TRACKER_UNAVAILABLE");
        verify(transaction, never()).complete(any(), any());
    }

    private AccountDeletionOperation operation() {
        return new AccountDeletionOperation(
                "operation-123",
                "user-123",
                "a".repeat(64),
                AccountDeletionStatus.PENDING,
                null,
                null,
                true,
                null,
                null,
                0,
                null,
                NOW,
                NOW,
                null,
                null,
                0L);
    }
}
