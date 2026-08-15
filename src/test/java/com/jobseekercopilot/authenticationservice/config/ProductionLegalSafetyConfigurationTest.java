package com.jobseekercopilot.authenticationservice.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class ProductionLegalSafetyConfigurationTest {

    private static final String TERMS_URL = "https://jobseekercopilot.com/terms";
    private static final String PRIVACY_URL = "https://jobseekercopilot.com/privacy";

    @Test
    void rejectsProductionUntilLegalDocumentsAreExplicitlyReviewed() {
        var configuration = configuration(false, "2026-08-15", TERMS_URL, PRIVACY_URL);

        IllegalStateException failure = assertThrows(
                IllegalStateException.class, configuration::validate);

        assertEquals(
                "Production registration requires explicitly reviewed legal documents.",
                failure.getMessage());
    }

    @Test
    void rejectsPlaceholderVersionsAndDocumentHostsAfterReviewIsAsserted() {
        var placeholderVersion = configuration(true, "draft-v1", TERMS_URL, PRIVACY_URL);
        var placeholderTerms = configuration(
                true, "2026-08-15", "https://legal.example.test/terms", PRIVACY_URL);

        assertThrows(IllegalStateException.class, placeholderVersion::validate);
        assertThrows(IllegalStateException.class, placeholderTerms::validate);
    }

    @Test
    void rejectsUnsafeProductionDocumentUrls() {
        var configuration = configuration(
                true, "2026-08-15", "http://jobseekercopilot.com/terms", PRIVACY_URL);

        IllegalStateException failure = assertThrows(
                IllegalStateException.class, configuration::validate);

        assertEquals(
                "Terms URL must be a reviewed, credential-free HTTPS URL.",
                failure.getMessage());
    }

    @Test
    void acceptsExplicitReviewedProductionConfiguration() {
        var configuration = configuration(true, "2026-08-15", TERMS_URL, PRIVACY_URL);

        assertDoesNotThrow(configuration::validate);
    }

    private ProductionLegalSafetyConfiguration configuration(
            boolean reviewed,
            String version,
            String termsUrl,
            String privacyUrl) {
        return new ProductionLegalSafetyConfiguration(
                reviewed, version, termsUrl, privacyUrl);
    }
}
