package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.model.AccountDeletionOperation;
import com.jobseekercopilot.authenticationservice.model.AccountDeletionStatus;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AccountDeletionCoordinator {

    private static final Logger log = LoggerFactory.getLogger(AccountDeletionCoordinator.class);

    private final AccountDeletionTransaction transaction;
    private final AccountLifecycleDownstreamClient downstream;
    private final JwtTokenProvider tokenProvider;

    @Value("${auth.account-lifecycle.completed-operation-retention:365d}")
    private Duration completedOperationRetention;

    public AccountDeletionOperation process(String operationId) {
        AccountDeletionOperation operation = transaction.get(operationId);
        if (operation.getStatus() == AccountDeletionStatus.COMPLETED) {
            return operation;
        }
        try {
            if (operation.isPaymentServiceRequired()
                    && operation.getPaymentServiceCompletedAt() == null) {
                downstream.revokePaymentAccess(operation.getUserId());
                operation = transaction.markStep(
                        operationId, AccountDeletionTransaction.Step.PAYMENT_SERVICE);
            }
            if (operation.getDocumentStoreCompletedAt() == null) {
                downstream.recoverablyDeleteDocuments(token(operation));
                operation = transaction.markStep(
                        operationId, AccountDeletionTransaction.Step.DOCUMENT_STORE);
            }
            if (operation.getApplicationTrackerCompletedAt() == null) {
                downstream.eraseApplications(token(operation));
                operation = transaction.markStep(
                        operationId, AccountDeletionTransaction.Step.APPLICATION_TRACKER);
            }
            if (operation.getUserProfileCompletedAt() == null) {
                downstream.eraseProfile(token(operation));
                transaction.markStep(
                        operationId, AccountDeletionTransaction.Step.USER_PROFILE);
            }
            AccountDeletionOperation completed = transaction.complete(
                    operationId, requireRetention());
            log.info("Account deletion completed operationId={} attemptCount={}",
                    operationId, completed.getAttemptCount());
            return completed;
        } catch (AccountLifecycleDownstreamException exception) {
            log.warn("Account deletion requires retry operationId={} errorCode={}",
                    operationId, exception.getSafeCode());
            return transaction.markFailure(operationId, exception.getSafeCode());
        } catch (RuntimeException exception) {
            log.error("Account deletion requires retry operationId={} error={}",
                    operationId, exception.getClass().getSimpleName());
            return transaction.markFailure(operationId, "COORDINATION_FAILED");
        }
    }

    private String token(AccountDeletionOperation operation) {
        return tokenProvider.generateAccountLifecycleToken(
                operation.getUserId(), operation.getId());
    }

    private Duration requireRetention() {
        if (completedOperationRetention == null
                || completedOperationRetention.isNegative()
                || completedOperationRetention.isZero()) {
            throw new IllegalStateException(
                    "Completed account-deletion retention must be positive");
        }
        return completedOperationRetention;
    }
}
