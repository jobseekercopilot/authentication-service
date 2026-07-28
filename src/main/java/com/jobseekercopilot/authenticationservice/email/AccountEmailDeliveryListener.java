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
        URI uri = URI.create(normalized);
        boolean localMode = "fixture".equals(deliveryMode)
                || "local-ses".equals(deliveryMode);
        boolean boundedLocalHttp = localMode
                && "http".equals(uri.getScheme())
                && isLoopbackHost(uri.getHost())
                && uri.getPort() > 0
                && (uri.getPath() == null || uri.getPath().isEmpty())
                && uri.getRawQuery() == null
                && uri.getRawFragment() == null
                && uri.getUserInfo() == null;
        if (!normalized.startsWith("https://") && !boundedLocalHttp) {
            throw new IllegalStateException("Account-email application base URL must use HTTPS");
        }
        return normalized;
    }

    private static boolean isLoopbackHost(String host) {
        return "localhost".equals(host)
                || "127.0.0.1".equals(host)
                || "::1".equals(host);
    }
}
