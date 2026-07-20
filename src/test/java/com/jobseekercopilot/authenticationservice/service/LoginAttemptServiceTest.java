package com.jobseekercopilot.authenticationservice.service;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LoginAttemptServiceTest {

    @Test
    void blocksAtThresholdAndRecoversAutomatically() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-20T12:00:00Z"));
        LoginAttemptService service = new LoginAttemptService(
                3, Duration.ofMinutes(15), Duration.ofMinutes(15), 100, clock);

        assertEquals(0, service.recordFailure("USER@example.test"));
        assertEquals(0, service.recordFailure("user@example.test"));
        assertEquals(900, service.recordFailure(" user@example.test "));
        assertEquals(900, service.retryAfterSecondsIfBlocked("user@example.test"));

        clock.advance(Duration.ofMinutes(15));

        assertEquals(0, service.retryAfterSecondsIfBlocked("user@example.test"));
        assertEquals(0, service.recordFailure("user@example.test"));
    }

    @Test
    void successfulAuthenticationClearsFailures() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-20T12:00:00Z"));
        LoginAttemptService service = new LoginAttemptService(
                2, Duration.ofMinutes(15), Duration.ofMinutes(15), 100, clock);

        service.recordFailure("user@example.test");
        service.recordSuccess("user@example.test");

        assertEquals(0, service.recordFailure("user@example.test"));
    }

    @Test
    void startsFreshAfterAttemptWindowExpires() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-20T12:00:00Z"));
        LoginAttemptService service = new LoginAttemptService(
                3, Duration.ofMinutes(15), Duration.ofMinutes(15), 100, clock);

        service.recordFailure("user@example.test");
        service.recordFailure("user@example.test");
        clock.advance(Duration.ofMinutes(15));

        assertEquals(0, service.recordFailure("user@example.test"));
    }

    @Test
    void rejectsUnsafeConfiguration() {
        Clock clock = Clock.systemUTC();

        assertThrows(IllegalArgumentException.class,
                () -> new LoginAttemptService(0, Duration.ofMinutes(1), Duration.ofMinutes(1), 1, clock));
        assertThrows(IllegalArgumentException.class,
                () -> new LoginAttemptService(1, Duration.ZERO, Duration.ofMinutes(1), 1, clock));
        assertThrows(IllegalArgumentException.class,
                () -> new LoginAttemptService(1, Duration.ofMinutes(1), Duration.ZERO, 1, clock));
        assertThrows(IllegalArgumentException.class,
                () -> new LoginAttemptService(1, Duration.ofMinutes(1), Duration.ofMinutes(1), 0, clock));
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
