package com.jobseekercopilot.authenticationservice.service;

import java.time.Instant;

public record PasswordResetEmailRequested(
        String accountId, String recipient, String rawToken, Instant expiresAt) {
}
