package com.jobseekercopilot.authenticationservice.model;

public record RegistrationLegalRequirements(
        String legalVersion,
        int minimumAge,
        String termsUrl,
        String privacyNoticeUrl) {
}
