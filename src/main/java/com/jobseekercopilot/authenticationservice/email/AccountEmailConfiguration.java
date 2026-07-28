package com.jobseekercopilot.authenticationservice.email;

import java.net.URI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ses.SesClient;

@Configuration
public class AccountEmailConfiguration {

    @Bean
    @ConditionalOnProperty(name = "auth.account-email.delivery-mode", havingValue = "ses")
    SesClient hostedAccountEmailSesClient(
            @Value("${auth.account-email.ses.region}") String region,
            @Value("${auth.account-email.ses.endpoint:}") String endpoint,
            @Value("${AWS_ACCESS_KEY_ID:}") String accessKeyId,
            @Value("${AWS_SECRET_ACCESS_KEY:}") String secretAccessKey) {
        requireRegion(region);
        if (endpoint != null && !endpoint.isBlank()) {
            throw new IllegalStateException(
                    "SES endpoint override is forbidden in hosted ses mode");
        }
        rejectDummyCredential(accessKeyId);
        rejectDummyCredential(secretAccessKey);
        return SesClient.builder()
                .region(Region.of(region))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .build();
    }

    @Bean
    @ConditionalOnProperty(
            name = "auth.account-email.delivery-mode",
            havingValue = "local-ses")
    SesClient localAccountEmailSesClient(
            @Value("${auth.account-email.ses.region}") String region,
            @Value("${auth.account-email.ses.endpoint}") String endpoint,
            @Value("${AWS_ACCESS_KEY_ID:}") String accessKeyId,
            @Value("${AWS_SECRET_ACCESS_KEY:}") String secretAccessKey) {
        requireRegion(region);
        URI checkedEndpoint = requireLocalStackEndpoint(endpoint);
        if (!"test".equals(accessKeyId) || !"test".equals(secretAccessKey)) {
            throw new IllegalStateException(
                    "local-ses requires the exact dummy LocalStack credentials");
        }
        return SesClient.builder()
                .region(Region.of(region))
                .endpointOverride(checkedEndpoint)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .build();
    }

    private static void requireRegion(String region) {
        if (region == null || region.isBlank()) {
            throw new IllegalStateException("SES region is required");
        }
    }

    private static URI requireLocalStackEndpoint(String endpoint) {
        if (endpoint == null || endpoint.isBlank()) {
            throw new IllegalStateException("LocalStack SES endpoint is required");
        }
        URI uri = URI.create(endpoint);
        if (!URI.create("http://localstack:4566").equals(uri)) {
            throw new IllegalStateException(
                    "local-ses endpoint must be the Compose-local LocalStack gateway");
        }
        return uri;
    }

    private static void rejectDummyCredential(String value) {
        if ("test".equals(value)) {
            throw new IllegalStateException(
                    "Dummy LocalStack credentials are forbidden in hosted ses mode");
        }
    }
}
