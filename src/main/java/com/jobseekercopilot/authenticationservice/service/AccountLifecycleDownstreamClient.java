package com.jobseekercopilot.authenticationservice.service;

import java.net.http.HttpClient;
import java.time.Duration;
import tools.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.ResourceAccessException;

@Component
public class AccountLifecycleDownstreamClient {

    private final RestClient profile;
    private final RestClient tracker;
    private final RestClient store;
    private final RestClient payment;
    private final String paymentServiceToken;

    @Autowired
    public AccountLifecycleDownstreamClient(
            @Value("${auth.account-lifecycle.user-profile-url}") String profileUrl,
            @Value("${auth.account-lifecycle.application-tracker-url}") String trackerUrl,
            @Value("${auth.account-lifecycle.document-store-url}") String storeUrl,
            @Value("${auth.account-lifecycle.payment-service-url}") String paymentUrl,
            @Value("${auth.account-lifecycle.payment-service-token}") String paymentServiceToken,
            @Value("${auth.account-lifecycle.connect-timeout:2s}") Duration connectTimeout,
            @Value("${auth.account-lifecycle.read-timeout:5s}") Duration readTimeout) {
        validateTimeout(connectTimeout, "connect");
        validateTimeout(readTimeout, "read");
        this.profile = client(profileUrl, connectTimeout, readTimeout);
        this.tracker = client(trackerUrl, connectTimeout, readTimeout);
        this.store = client(storeUrl, connectTimeout, readTimeout);
        this.payment = client(paymentUrl, connectTimeout, readTimeout);
        this.paymentServiceToken = requireServiceToken(paymentServiceToken);
    }

    AccountLifecycleDownstreamClient(
            RestClient profile,
            RestClient tracker,
            RestClient store,
            RestClient payment,
            String paymentServiceToken) {
        this.profile = profile;
        this.tracker = tracker;
        this.store = store;
        this.payment = payment;
        this.paymentServiceToken = requireServiceToken(paymentServiceToken);
    }

    public JsonNode exportProfile(String accessToken) {
        return get(profile, "/api/profiles/me/export", accessToken, "PROFILE");
    }

    public JsonNode exportApplications(String accessToken) {
        return get(tracker, "/api/v1/applications/account-export", accessToken, "TRACKER");
    }

    public JsonNode exportDocuments(String accessToken) {
        return get(store, "/api/v1/documents/account-export", accessToken, "STORE");
    }

    public JsonNode exportPayments(String owner) {
        JsonNode response = invoke(() -> payment.get()
                .uri("/internal/v2/payments/owners/{owner}/export", owner)
                .headers(headers -> paymentHeaders(headers, owner))
                .retrieve()
                .body(JsonNode.class), "PAYMENT");
        if (response == null
                || !response.isObject()
                || !"payment-export-v1".equals(response.path("schemaVersion").asText())
                || !owner.equals(response.path("ownerId").asText())) {
            throw new AccountLifecycleDownstreamException(
                    "PAYMENT_INVALID_RESPONSE", new IllegalStateException(
                            "Payment export response failed owner/schema validation"));
        }
        return response;
    }

    public void revokePaymentAccess(String owner) {
        JsonNode response = invoke(() -> payment.post()
                .uri("/internal/v2/payments/owners/{owner}/revoke-access", owner)
                .headers(headers -> paymentHeaders(headers, owner))
                .retrieve()
                .body(JsonNode.class), "PAYMENT");
        boolean pendingProviderSessions = response != null
                && response.path("providerSessionsRequireExpiry").asBoolean(true);
        JsonNode providerSessions = response == null
                ? null
                : response.path("providerCheckoutSessionsToExpire");
        if (response == null
                || !response.isObject()
                || !"ACCESS_REVOKED_RECORDS_RETAINED".equals(response.path("status").asText())
                || pendingProviderSessions
                || providerSessions == null
                || !providerSessions.isArray()
                || !providerSessions.isEmpty()) {
            throw new AccountLifecycleDownstreamException(
                    "PAYMENT_INVALID_RESPONSE", new IllegalStateException(
                            "Payment lifecycle response did not confirm provider reconciliation"));
        }
    }

    public void recoverablyDeleteDocuments(String lifecycleToken) {
        invoke(() -> store.post()
                .uri("/internal/account-lifecycle/recoverable-delete")
                .headers(headers -> headers.setBearerAuth(lifecycleToken))
                .retrieve()
                .toBodilessEntity(), "STORE");
    }

    public void eraseApplications(String lifecycleToken) {
        delete(tracker, lifecycleToken, "TRACKER");
    }

    public void eraseProfile(String lifecycleToken) {
        delete(profile, lifecycleToken, "PROFILE");
    }

    private JsonNode get(
            RestClient client, String path, String accessToken, String service) {
        return invoke(() -> client.get()
                .uri(path)
                .headers(headers -> headers.setBearerAuth(accessToken))
                .retrieve()
                .body(JsonNode.class), service);
    }

    private void delete(RestClient client, String lifecycleToken, String service) {
        invoke(() -> client.delete()
                .uri("/internal/account-lifecycle/personal-data")
                .headers(headers -> headers.setBearerAuth(lifecycleToken))
                .retrieve()
                .toBodilessEntity(), service);
    }

    private void paymentHeaders(org.springframework.http.HttpHeaders headers, String owner) {
        headers.set("X-Service-Token", paymentServiceToken);
        headers.set("X-Payment-Owner", owner);
    }

    private <T> T invoke(DownstreamCall<T> call, String service) {
        try {
            return call.execute();
        } catch (RestClientResponseException exception) {
            throw new AccountLifecycleDownstreamException(
                    service + "_HTTP_" + exception.getStatusCode().value(), exception);
        } catch (ResourceAccessException exception) {
            throw new AccountLifecycleDownstreamException(
                    service + "_UNAVAILABLE", exception);
        } catch (RuntimeException exception) {
            if (exception instanceof AccountLifecycleDownstreamException downstream) {
                throw downstream;
            }
            throw new AccountLifecycleDownstreamException(
                    service + "_FAILED", exception);
        }
    }

    private RestClient client(
            String baseUrl, Duration connectTimeout, Duration readTimeout) {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("Account-lifecycle service URL is required");
        }
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .build();
        JdkClientHttpRequestFactory requestFactory =
                new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(readTimeout);
        return RestClient.builder()
                .requestFactory(requestFactory)
                .baseUrl(baseUrl)
                .build();
    }

    private void validateTimeout(Duration timeout, String name) {
        if (timeout == null || timeout.isZero() || timeout.isNegative()) {
            throw new IllegalStateException(
                    "Account-lifecycle " + name + " timeout must be positive");
        }
    }

    private String requireServiceToken(String token) {
        if (token == null
                || token.length() < 32
                || token.length() > 512
                || token.chars().anyMatch(value -> Character.isISOControl(value))) {
            throw new IllegalStateException(
                    "Account-lifecycle payment service token must be 32-512 characters");
        }
        return token;
    }

    @FunctionalInterface
    private interface DownstreamCall<T> {
        T execute();
    }
}
