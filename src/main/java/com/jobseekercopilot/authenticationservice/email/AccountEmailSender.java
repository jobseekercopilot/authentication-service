package com.jobseekercopilot.authenticationservice.email;

import java.net.URI;
import java.time.Instant;

public interface AccountEmailSender {

    void sendPasswordReset(
            String accountId,
            String recipient,
            URI resetLink,
            Instant expiresAt);

    void sendPasswordChanged(String accountId, String recipient);
}
