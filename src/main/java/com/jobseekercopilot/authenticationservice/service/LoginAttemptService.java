package com.jobseekercopilot.authenticationservice.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {

    private final int maximumFailures;
    private final Duration attemptWindow;
    private final Duration lockDuration;
    private final int maximumTrackedPrincipals;
    private final Clock clock;
    private final ConcurrentHashMap<String, AttemptState> attempts = new ConcurrentHashMap<>();

    public LoginAttemptService(
            @Value("${auth.login.maximum-failures:10}") int maximumFailures,
            @Value("${auth.login.attempt-window:15m}") Duration attemptWindow,
            @Value("${auth.login.lock-duration:15m}") Duration lockDuration,
            @Value("${auth.login.maximum-tracked-principals:10000}") int maximumTrackedPrincipals,
            Clock clock) {
        if (maximumFailures < 1 || attemptWindow.isNegative() || attemptWindow.isZero()
                || lockDuration.isNegative() || lockDuration.isZero() || maximumTrackedPrincipals < 1) {
            throw new IllegalArgumentException("Login attempt limits must be positive");
        }
        this.maximumFailures = maximumFailures;
        this.attemptWindow = attemptWindow;
        this.lockDuration = lockDuration;
        this.maximumTrackedPrincipals = maximumTrackedPrincipals;
        this.clock = clock;
    }

    public long retryAfterSecondsIfBlocked(String email) {
        Instant now = clock.instant();
        AttemptState state = attempts.get(principalKey(email));
        if (state == null || state.blockedUntil() == null || !state.blockedUntil().isAfter(now)) {
            return 0;
        }
        return Math.max(1, Duration.between(now, state.blockedUntil()).toSeconds());
    }

    public long recordFailure(String email) {
        Instant now = clock.instant();
        String key = principalKey(email);
        makeCapacityFor(key, now);
        AttemptState state = attempts.compute(key, (ignored, existing) -> {
            if (existing == null || !existing.windowStartedAt().plus(attemptWindow).isAfter(now)) {
                return new AttemptState(1, now, null, now);
            }
            int failures = existing.failures() + 1;
            Instant blockedUntil = failures >= maximumFailures ? now.plus(lockDuration) : existing.blockedUntil();
            return new AttemptState(failures, existing.windowStartedAt(), blockedUntil, now);
        });
        if (state.blockedUntil() == null) {
            return 0;
        }
        return Math.max(1, Duration.between(now, state.blockedUntil()).toSeconds());
    }

    public void recordSuccess(String email) {
        attempts.remove(principalKey(email));
    }

    private void makeCapacityFor(String key, Instant now) {
        if (attempts.containsKey(key) || attempts.size() < maximumTrackedPrincipals) {
            return;
        }
        attempts.entrySet().removeIf(entry -> entry.getValue().lastAttemptAt().plus(attemptWindow)
                .plus(lockDuration).isBefore(now));
        if (attempts.size() >= maximumTrackedPrincipals) {
            attempts.entrySet().stream()
                    .min(Comparator.comparing(entry -> entry.getValue().lastAttemptAt()))
                    .ifPresent(entry -> attempts.remove(entry.getKey(), entry.getValue()));
        }
    }

    private String principalKey(String email) {
        String normalized = email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(normalized.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    private record AttemptState(
            int failures,
            Instant windowStartedAt,
            Instant blockedUntil,
            Instant lastAttemptAt) {
    }
}
