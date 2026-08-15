package com.jobseekercopilot.authenticationservice.model;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;

public record PersonalDataExport(
        String schemaVersion,
        Instant generatedAt,
        UserAccountResponse account,
        RegistrationLegalAcceptanceResponse registrationLegalAcceptance,
        JsonNode profile,
        JsonNode applications,
        JsonNode documents) {
}
