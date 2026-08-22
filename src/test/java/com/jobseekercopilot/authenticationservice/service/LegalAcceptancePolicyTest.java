package com.jobseekercopilot.authenticationservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.jobseekercopilot.authenticationservice.exception.LegalAcceptanceException;
import com.jobseekercopilot.authenticationservice.model.RegisterRequest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class LegalAcceptancePolicyTest {

    private static final Instant NOW = Instant.parse("2026-08-15T01:02:03Z");
    private final LegalAcceptancePolicy policy = new LegalAcceptancePolicy(
            "2026-08-15",
            "https://jobseekercopilot.com/terms",
            "https://jobseekercopilot.com/privacy",
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void recordsExactReviewedAcceptanceWithoutClientSelectedFacts() {
        RegisterRequest request = accepted("2026-08-15");

        policy.requireAccepted(request);
        var acceptance = policy.acceptanceFor("owner-123");

        assertThat(acceptance.getUserId()).isEqualTo("owner-123");
        assertThat(acceptance.getLegalVersion()).isEqualTo("2026-08-15");
        assertThat(acceptance.isTermsAccepted()).isTrue();
        assertThat(acceptance.isPrivacyNoticeAcknowledged()).isTrue();
        assertThat(acceptance.isAgeEligibilityConfirmed()).isTrue();
        assertThat(acceptance.getAcceptedAt()).isEqualTo(NOW);
        assertThat(policy.requirements().minimumAge()).isEqualTo(18);
        assertThat(policy.requirements().termsUrl())
                .isEqualTo("https://jobseekercopilot.com/terms");
    }

    @Test
    void rejectsMissingOrPartialAcceptance() {
        RegisterRequest missing = new RegisterRequest(
                "User", "user@example.test", "A valid local passphrase",
                true, true, false, "2026-08-15");

        assertThatThrownBy(() -> policy.requireAccepted(missing))
                .isInstanceOf(LegalAcceptanceException.class)
                .extracting(error -> ((LegalAcceptanceException) error).getCode())
                .isEqualTo("LEGAL_ACCEPTANCE_REQUIRED");
    }

    @Test
    void rejectsStaleOrInventedLegalVersion() {
        assertThatThrownBy(() -> policy.requireAccepted(accepted("2026-07-01")))
                .isInstanceOf(LegalAcceptanceException.class)
                .extracting(error -> ((LegalAcceptanceException) error).getCode())
                .isEqualTo("LEGAL_VERSION_OUTDATED");
    }

    @Test
    void rejectsUnsafeServerConfiguration() {
        assertThatThrownBy(() -> new LegalAcceptancePolicy(
                        "https://example.test/terms?secret=value",
                        "https://jobseekercopilot.com/terms",
                        "https://jobseekercopilot.com/privacy",
                        Clock.systemUTC()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("legal version");

        assertThatThrownBy(() -> new LegalAcceptancePolicy(
                        "2026-08-15",
                        "http://jobseekercopilot.com/terms",
                        "https://jobseekercopilot.com/privacy",
                        Clock.systemUTC()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Terms URL");
    }

    private RegisterRequest accepted(String version) {
        return new RegisterRequest(
                "User", "user@example.test", "A valid local passphrase",
                true, true, true, version);
    }
}
