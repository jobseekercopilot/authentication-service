package com.jobseekercopilot.authenticationservice.email;

import java.net.URI;
import java.time.Instant;

public record FixtureAccountEmail(
        String purpose,
        String accountId,
        String recipient,
        URI actionUrl,
        Instant expiresAt,
        Instant sentAt) {
}
