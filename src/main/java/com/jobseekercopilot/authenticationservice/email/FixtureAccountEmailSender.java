package com.jobseekercopilot.authenticationservice.email;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(
        name = "auth.account-email.delivery-mode",
        havingValue = "fixture",
        matchIfMissing = true)
public class FixtureAccountEmailSender implements AccountEmailSender {

    public static final String PASSWORD_RESET = "PASSWORD_RESET";
    public static final String PASSWORD_CHANGED = "PASSWORD_CHANGED";

    private final Deque<FixtureAccountEmail> messages = new ArrayDeque<>();
    private final Clock clock;
    private final int maximumMessages;

    public FixtureAccountEmailSender(
            Clock clock,
            @Value("${auth.account-email.fixture.maximum-messages:1000}") int maximumMessages) {
        if (maximumMessages < 1 || maximumMessages > 10_000) {
            throw new IllegalStateException("Fixture account-email capacity must be between 1 and 10000");
        }
        this.clock = clock;
        this.maximumMessages = maximumMessages;
    }

    @Override
    public void sendPasswordReset(
            String accountId, String recipient, URI resetLink, Instant expiresAt) {
        add(new FixtureAccountEmail(
                PASSWORD_RESET, accountId, recipient, resetLink, expiresAt, clock.instant()));
    }

    @Override
    public void sendPasswordChanged(String accountId, String recipient) {
        add(new FixtureAccountEmail(
                PASSWORD_CHANGED, accountId, recipient, null, null, clock.instant()));
    }

    public synchronized Optional<FixtureAccountEmail> latest(String recipient, String purpose) {
        return messages.stream()
                .filter(message -> message.recipient().equalsIgnoreCase(recipient))
                .filter(message -> message.purpose().equals(purpose))
                .findFirst();
    }

    public synchronized void clear() {
        messages.clear();
    }

    private synchronized void add(FixtureAccountEmail message) {
        messages.addFirst(message);
        while (messages.size() > maximumMessages) {
            messages.removeLast();
        }
    }
}
