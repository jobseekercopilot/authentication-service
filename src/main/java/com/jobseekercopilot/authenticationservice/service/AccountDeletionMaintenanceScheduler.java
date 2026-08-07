package com.jobseekercopilot.authenticationservice.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AccountDeletionMaintenanceScheduler {

    private static final Logger log = LoggerFactory.getLogger(
            AccountDeletionMaintenanceScheduler.class);

    private final AccountDeletionTransaction transaction;
    private final AccountDeletionCoordinator coordinator;

    @Value("${auth.account-lifecycle.recovery-batch-size:25}")
    private int recoveryBatchSize;

    @Scheduled(
            initialDelayString = "${auth.account-lifecycle.recovery-initial-delay:PT30S}",
            fixedDelayString = "${auth.account-lifecycle.recovery-delay:PT30S}")
    void recover() {
        if (recoveryBatchSize < 1 || recoveryBatchSize > 250) {
            throw new IllegalStateException(
                    "Account-deletion recovery batch size must be between 1 and 250");
        }
        transaction.unresolved(recoveryBatchSize)
                .forEach(operation -> coordinator.process(operation.getId()));
    }

    @Scheduled(cron = "${auth.account-lifecycle.audit-cleanup-cron:0 17 3 * * *}")
    void removeExpiredCompletedAudit() {
        int removed = transaction.removeExpiredCompleted();
        if (removed > 0) {
            log.info("Expired account-deletion audit records removed count={}", removed);
        }
    }
}
