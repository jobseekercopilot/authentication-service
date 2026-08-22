package com.jobseekercopilot.authenticationservice.model;

import java.time.Instant;

public record AccountDeletionResponse(
        String operationId,
        AccountDeletionStatus status,
        Instant acceptedAt,
        Instant completedAt) {
}
