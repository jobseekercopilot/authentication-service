package com.jobseekercopilot.authenticationservice.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@NoArgsConstructor
@Schema(additionalProperties = Schema.AdditionalPropertiesValue.FALSE)
public class RegisterRequest {
    private String name;
    private String email;
    private String password;

    @Schema(
            requiredMode = Schema.RequiredMode.REQUIRED,
            description = "Must be true after the user has actively accepted the current Terms of Use.")
    private boolean termsAccepted;

    @Schema(
            requiredMode = Schema.RequiredMode.REQUIRED,
            description = "Must be true after the user has acknowledged the current Privacy Notice.")
    private boolean privacyNoticeAcknowledged;

    @Schema(
            requiredMode = Schema.RequiredMode.REQUIRED,
            description = "Must be true to confirm the registrant is at least 18 years old.")
    private boolean ageEligibilityConfirmed;

    @Schema(
            requiredMode = Schema.RequiredMode.REQUIRED,
            minLength = 1,
            maxLength = 64,
            description = "Exact reviewed legal-document version displayed to the user.")
    private String legalVersion;

    public RegisterRequest(String name, String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;
    }

    public RegisterRequest(
            String name,
            String email,
            String password,
            boolean termsAccepted,
            boolean privacyNoticeAcknowledged,
            boolean ageEligibilityConfirmed,
            String legalVersion) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.termsAccepted = termsAccepted;
        this.privacyNoticeAcknowledged = privacyNoticeAcknowledged;
        this.ageEligibilityConfirmed = ageEligibilityConfirmed;
        this.legalVersion = legalVersion;
    }
}
