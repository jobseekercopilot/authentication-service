package com.jobseekercopilot.authenticationservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "registration_legal_acceptance")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RegistrationLegalAcceptance {

    @Id
    @Column(name = "user_id", nullable = false, length = 36)
    private String userId;

    @Column(name = "legal_version", nullable = false, length = 64)
    private String legalVersion;

    @Column(name = "terms_accepted", nullable = false)
    private boolean termsAccepted;

    @Column(name = "privacy_notice_acknowledged", nullable = false)
    private boolean privacyNoticeAcknowledged;

    @Column(name = "age_eligibility_confirmed", nullable = false)
    private boolean ageEligibilityConfirmed;

    @Column(name = "accepted_at", nullable = false)
    private Instant acceptedAt;
}
