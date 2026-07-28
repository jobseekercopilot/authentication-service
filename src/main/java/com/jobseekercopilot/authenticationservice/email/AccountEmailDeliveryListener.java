package com.jobseekercopilot.authenticationservice.email;

import com.jobseekercopilot.authenticationservice.service.PasswordChanged;
import com.jobseekercopilot.authenticationservice.service.PasswordResetEmailRequested;
import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class AccountEmailDeliveryListener {

    private static final Logger log = LoggerFactory.getLogger(AccountEmailDeliveryListener.class);

    private final AccountEmailSender sender;
    private final String applicationBaseUrl;

    public AccountEmailDeliveryListener(
            AccountEmailSender sender,
            @Value("${auth.account-email.application-base-url}") String applicationBaseUrl,
            @Value("${auth.account-email.delivery-mode:fixture}") String deliveryMode) {
        this.sender = sender;
        this.applicationBaseUrl = validateBaseUrl(applicationBaseUrl, deliveryMode);
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onPasswordResetRequested(PasswordResetEmailRequested event) {
        try {
            URI resetLink = URI.create(
                    applicationBaseUrl + "/reset-password#token=" + event.rawToken());
            sender.sendPasswordReset(
                    event.accountId(), event.recipient(), resetLink, event.expiresAt());
            log.info("Account email delivered accountId={} purpose=password-reset",
                    event.accountId());
        } catch (RuntimeException exception) {
            log.error("Account email delivery failed accountId={} purpose=password-reset error={}",
                    event.accountId(), exception.getClass().getSimpleName());
        }
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onPasswordChanged(PasswordChanged event) {
        try {
            sender.sendPasswordChanged(event.accountId(), event.recipient());
            log.info("Account email delivered accountId={} purpose=password-changed",
                    event.accountId());
        } catch (RuntimeException exception) {
            log.error("Account email delivery failed accountId={} purpose=password-changed error={}",
                    event.accountId(), exception.getClass().getSimpleName());
        }
    }

    private static String validateBaseUrl(String value, String deliveryMode) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Account-email application base URL is required");
        }
        String normalized = value.endsWith("/")
                ? value.substring(0, value.length() - 1)
                : value;
        boolean fixtureHttp = "fixture".equals(deliveryMode) && normalized.startsWith("http://");
        if (!normalized.startsWith("https://") && !fixtureHttp) {
            throw new IllegalStateException("Account-email application base URL must use HTTPS");
        }
        return normalized;
    }
}
