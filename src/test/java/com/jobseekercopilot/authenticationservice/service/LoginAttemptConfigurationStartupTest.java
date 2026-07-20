package com.jobseekercopilot.authenticationservice.service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoginAttemptConfigurationStartupTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
            .withUserConfiguration(LoginAttemptTestConfiguration.class);

    @Test
    void applicationContextFailsSafelyForNonPositiveLimits() {
        contextRunner
                .withPropertyValues("auth.login.maximum-failures=0")
                .run(context -> {
                    Throwable failure = context.getStartupFailure();
                    assertNotNull(failure);
                    assertTrue(messageChain(failure).contains("Login attempt limits must be positive"));
                });
    }

    @Test
    void applicationContextStartsWithPositiveLimits() {
        contextRunner.run(context -> assertTrue(context.isRunning()));
    }

    private String messageChain(Throwable failure) {
        StringBuilder messages = new StringBuilder();
        for (Throwable current = failure; current != null; current = current.getCause()) {
            if (current.getMessage() != null) {
                messages.append(current.getMessage()).append(' ');
            }
        }
        return messages.toString();
    }

    @Configuration(proxyBeanMethods = false)
    static class LoginAttemptTestConfiguration {

        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }

        @Bean
        LoginAttemptService loginAttemptService(
                @org.springframework.beans.factory.annotation.Value("${auth.login.maximum-failures:10}") int maximumFailures,
                @org.springframework.beans.factory.annotation.Value("${auth.login.maximum-tracked-principals:10000}") int maximumTrackedPrincipals,
                Clock clock) {
            return new LoginAttemptService(maximumFailures, Duration.ofMinutes(15), Duration.ofMinutes(15),
                    maximumTrackedPrincipals, clock);
        }
    }
}
