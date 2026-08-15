package com.jobseekercopilot.authenticationservice.model;

import java.time.Instant;
import tools.jackson.databind.JsonNode;

public record PersonalDataExport(
        String schemaVersion,
        Instant generatedAt,
        UserAccountResponse account,
        RegistrationLegalAcceptanceResponse registrationLegalAcceptance,
        JsonNode profile,
        JsonNode applications,
        JsonNode documents,
        JsonNode payments) {
}
