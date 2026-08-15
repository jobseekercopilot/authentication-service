package com.jobseekercopilot.authenticationservice.config;

import jakarta.annotation.PostConstruct;
import java.net.URI;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("production")
public class ProductionLegalSafetyConfiguration {

    private static final Pattern VERSION =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");
    private static final Pattern PLACEHOLDER_VERSION = Pattern.compile(
            "(?:^|[._-])(?:todo|tbd|tbc|draft|example|local|pending|placeholder|replace|test|unreviewed)(?:$|[._-])",
            Pattern.CASE_INSENSITIVE);
    private static final Set<String> PLACEHOLDER_HOSTS = Set.of(
            "example.com", "example.org", "example.net", "localhost");

    private final boolean documentsReviewed;
    private final String currentVersion;
    private final String termsUrl;
    private final String privacyNoticeUrl;

    public ProductionLegalSafetyConfiguration(
            @Value("${auth.legal.documents-reviewed:false}") boolean documentsReviewed,
            @Value("${auth.legal.current-version}") String currentVersion,
            @Value("${auth.legal.terms-url}") String termsUrl,
            @Value("${auth.legal.privacy-notice-url}") String privacyNoticeUrl) {
        this.documentsReviewed = documentsReviewed;
        this.currentVersion = currentVersion;
        this.termsUrl = termsUrl;
        this.privacyNoticeUrl = privacyNoticeUrl;
    }

    @PostConstruct
    void validate() {
        if (!documentsReviewed) {
            throw new IllegalStateException(
                    "Production registration requires explicitly reviewed legal documents.");
        }
        if (currentVersion == null
                || !VERSION.matcher(currentVersion).matches()
                || PLACEHOLDER_VERSION.matcher(currentVersion).find()) {
            throw new IllegalStateException(
                    "Production registration legal version must be reviewed and non-placeholder.");
        }
        requireReviewedHttpsUrl(termsUrl, "Terms");
        requireReviewedHttpsUrl(privacyNoticeUrl, "Privacy Notice");
    }

    private void requireReviewedHttpsUrl(String value, String name) {
        try {
            URI uri = URI.create(value == null ? "" : value);
            String host = uri.getHost();
            if (!"https".equalsIgnoreCase(uri.getScheme())
                    || host == null
                    || host.isBlank()
                    || uri.getUserInfo() != null
                    || isPlaceholderHost(host)) {
                throw new IllegalArgumentException();
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException(
                    name + " URL must be a reviewed, credential-free HTTPS URL.");
        }
    }

    private boolean isPlaceholderHost(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);
        return PLACEHOLDER_HOSTS.contains(normalized)
                || normalized.endsWith(".example.com")
                || normalized.endsWith(".example.org")
                || normalized.endsWith(".example.net")
                || normalized.endsWith(".example")
                || normalized.endsWith(".invalid")
                || normalized.endsWith(".localhost")
                || normalized.endsWith(".test");
    }
}
