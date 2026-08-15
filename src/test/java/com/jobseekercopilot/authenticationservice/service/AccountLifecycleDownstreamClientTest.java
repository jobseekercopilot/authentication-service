package com.jobseekercopilot.authenticationservice.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import tools.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class AccountLifecycleDownstreamClientTest {

    private static final String TOKEN = "payment-lifecycle-service-token-0001";
    private static final String OWNER = "11111111-1111-4111-8111-111111111111";

    private MockRestServiceServer paymentServer;
    private AccountLifecycleDownstreamClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder paymentBuilder = RestClient.builder()
                .baseUrl("https://payment.internal.test");
        paymentServer = MockRestServiceServer.bindTo(paymentBuilder).build();
        RestClient unused = RestClient.create("https://unused.internal.test");
        client = new AccountLifecycleDownstreamClient(
                unused, unused, unused, paymentBuilder.build(), TOKEN);
    }

    @Test
    void exportsOnlyTheMatchingOwnersVersionedPaymentRecord() {
        paymentServer.expect(requestTo(
                        "https://payment.internal.test/internal/v2/payments/owners/"
                                + OWNER + "/export"))
                .andExpect(method(GET))
                .andExpect(this::assertTrustedPaymentHeaders)
                .andRespond(withSuccess("""
                        {"schemaVersion":"payment-export-v1","ownerId":"%s","orders":[]}
                        """.formatted(OWNER), MediaType.APPLICATION_JSON));

        JsonNode result = client.exportPayments(OWNER);

        assertEquals("payment-export-v1", result.path("schemaVersion").asText());
        paymentServer.verify();
    }

    @Test
    void rejectsAValidPaymentExportForAnotherOwner() {
        paymentServer.expect(requestTo(
                        "https://payment.internal.test/internal/v2/payments/owners/"
                                + OWNER + "/export"))
                .andRespond(withSuccess("""
                        {"schemaVersion":"payment-export-v1","ownerId":"another-owner"}
                        """, MediaType.APPLICATION_JSON));

        AccountLifecycleDownstreamException exception = assertThrows(
                AccountLifecycleDownstreamException.class,
                () -> client.exportPayments(OWNER));

        assertEquals("PAYMENT_INVALID_RESPONSE", exception.getSafeCode());
        paymentServer.verify();
    }

    @Test
    void confirmsPaymentAccessRevocationOnlyAfterProviderSessionsAreReconciled() {
        paymentServer.expect(requestTo(
                        "https://payment.internal.test/internal/v2/payments/owners/"
                                + OWNER + "/revoke-access"))
                .andExpect(method(POST))
                .andExpect(this::assertTrustedPaymentHeaders)
                .andRespond(withSuccess("""
                        {
                          "status":"ACCESS_REVOKED_RECORDS_RETAINED",
                          "providerSessionsRequireExpiry":false,
                          "providerCheckoutSessionsToExpire":[]
                        }
                        """, MediaType.APPLICATION_JSON));

        client.revokePaymentAccess(OWNER);

        paymentServer.verify();
    }

    @Test
    void preservesRetryablePaymentServiceFailures() {
        paymentServer.expect(requestTo(
                        "https://payment.internal.test/internal/v2/payments/owners/"
                                + OWNER + "/revoke-access"))
                .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));

        AccountLifecycleDownstreamException exception = assertThrows(
                AccountLifecycleDownstreamException.class,
                () -> client.revokePaymentAccess(OWNER));

        assertEquals("PAYMENT_HTTP_503", exception.getSafeCode());
        paymentServer.verify();
    }

    private void assertTrustedPaymentHeaders(org.springframework.http.HttpRequest request) {
        assertEquals(TOKEN, request.getHeaders().getFirst("X-Service-Token"));
        assertEquals(OWNER, request.getHeaders().getFirst("X-Payment-Owner"));
        assertNull(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
        assertNull(request.getHeaders().getFirst("X-User-Id"));
    }
}
