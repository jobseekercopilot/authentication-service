package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.LegalAcceptanceException;
import com.jobseekercopilot.authenticationservice.model.RegisterRequest;
import com.jobseekercopilot.authenticationservice.model.RegistrationLegalAcceptance;
import com.jobseekercopilot.authenticationservice.model.RegistrationLegalRequirements;
import java.net.URI;
import java.time.Clock;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class LegalAcceptancePolicy {

    private static final Pattern VERSION =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");

    private final String currentVersion;
    private final Clock clock;
    private final String termsUrl;
    private final String privacyNoticeUrl;

    public LegalAcceptancePolicy(
            @Value("${auth.legal.current-version}") String currentVersion,
            @Value("${auth.legal.terms-url}") String termsUrl,
            @Value("${auth.legal.privacy-notice-url}") String privacyNoticeUrl,
            Clock clock) {
        if (currentVersion == null || !VERSION.matcher(currentVersion).matches()) {
            throw new IllegalStateException(
                    "Current registration legal version must be 1-64 safe characters");
        }
        this.currentVersion = currentVersion;
        this.termsUrl = requireHttpsUrl(termsUrl, "Terms");
        this.privacyNoticeUrl = requireHttpsUrl(privacyNoticeUrl, "Privacy Notice");
        this.clock = clock;
    }

    public void requireAccepted(RegisterRequest request) {
        if (request == null
                || !request.isTermsAccepted()
                || !request.isPrivacyNoticeAcknowledged()
                || !request.isAgeEligibilityConfirmed()) {
            throw LegalAcceptanceException.required();
        }
        if (!currentVersion.equals(request.getLegalVersion())) {
            throw LegalAcceptanceException.outdated();
        }
    }

    public RegistrationLegalAcceptance acceptanceFor(String userId) {
        return new RegistrationLegalAcceptance(
                userId,
                currentVersion,
                true,
                true,
                true,
                clock.instant());
    }

    public String currentVersion() {
        return currentVersion;
    }

    public RegistrationLegalRequirements requirements() {
        return new RegistrationLegalRequirements(
                currentVersion, 18, termsUrl, privacyNoticeUrl);
    }

    private String requireHttpsUrl(String value, String name) {
        try {
            URI uri = URI.create(value == null ? "" : value);
            if (!"https".equalsIgnoreCase(uri.getScheme())
                    || uri.getHost() == null
                    || uri.getHost().isBlank()
                    || uri.getUserInfo() != null) {
                throw new IllegalArgumentException();
            }
            return uri.toASCIIString();
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException(
                    name + " URL must be an absolute credential-free HTTPS URL");
        }
    }
}
