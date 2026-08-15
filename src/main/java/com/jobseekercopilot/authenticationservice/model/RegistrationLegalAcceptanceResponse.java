package com.jobseekercopilot.authenticationservice.model;

import java.time.Instant;

public record RegistrationLegalAcceptanceResponse(
        String legalVersion,
        boolean termsAccepted,
        boolean privacyNoticeAcknowledged,
        boolean ageEligibilityConfirmed,
        Instant acceptedAt) {

    public static RegistrationLegalAcceptanceResponse from(
            RegistrationLegalAcceptance acceptance) {
        return new RegistrationLegalAcceptanceResponse(
                acceptance.getLegalVersion(),
                acceptance.isTermsAccepted(),
                acceptance.isPrivacyNoticeAcknowledged(),
                acceptance.isAgeEligibilityConfirmed(),
                acceptance.getAcceptedAt());
    }
}
