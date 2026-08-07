package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.model.AccountDeletionResponse;
import com.jobseekercopilot.authenticationservice.model.PersonalDataExport;
import java.time.Clock;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AccountLifecycleService {

    private final AuthService authService;
    private final AccountDeletionTransaction deletionTransaction;
    private final AccountDeletionCoordinator deletionCoordinator;
    private final AccountLifecycleDownstreamClient downstream;
    private final Clock clock;
    private final Duration recentAuthenticationAge;

    public AccountLifecycleService(
            AuthService authService,
            AccountDeletionTransaction deletionTransaction,
            AccountDeletionCoordinator deletionCoordinator,
            AccountLifecycleDownstreamClient downstream,
            Clock clock,
            @Value("${auth.account-lifecycle.recent-authentication-age:15m}")
            Duration recentAuthenticationAge) {
        if (recentAuthenticationAge == null
                || recentAuthenticationAge.isZero()
                || recentAuthenticationAge.isNegative()
                || recentAuthenticationAge.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new IllegalStateException(
                    "Recent-authentication age must be between 1ms and 15 minutes");
        }
        this.authService = authService;
        this.deletionTransaction = deletionTransaction;
        this.deletionCoordinator = deletionCoordinator;
        this.downstream = downstream;
        this.clock = clock;
        this.recentAuthenticationAge = recentAuthenticationAge;
    }

    public PersonalDataExport export(String accessToken) {
        String userId = authService.validateRecentlyAuthenticated(
                accessToken, recentAuthenticationAge);
        return new PersonalDataExport(
                "job-seeker-copilot-personal-data.v1",
                clock.instant(),
                authService.getUserAccount(userId),
                downstream.exportProfile(accessToken),
                downstream.exportApplications(accessToken),
                downstream.exportDocuments(accessToken));
    }

    public AccountDeletionResponse delete(String accessToken, String idempotencyKey) {
        String userId = authService.validateRecentlyAuthenticated(
                accessToken, recentAuthenticationAge);
        var operation = deletionTransaction.start(userId, idempotencyKey);
        operation = deletionCoordinator.process(operation.getId());
        return new AccountDeletionResponse(
                operation.getId(),
                operation.getStatus(),
                operation.getCreatedAt(),
                operation.getCompletedAt());
    }
}
