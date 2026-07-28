package com.jobseekercopilot.authenticationservice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jobseekercopilot.authenticationservice.email.FixtureAccountEmailSender;
import com.jobseekercopilot.authenticationservice.model.LoginRequest;
import com.jobseekercopilot.authenticationservice.model.PasswordResetCompletionRequest;
import com.jobseekercopilot.authenticationservice.model.PasswordResetRequest;
import com.jobseekercopilot.authenticationservice.model.PasswordResetToken;
import com.jobseekercopilot.authenticationservice.model.RegisterRequest;
import com.jobseekercopilot.authenticationservice.repository.PasswordResetTokenRepository;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "auth.password-reset.request-cooldown=0s",
        "environment-data.enabled=true"
})
@AutoConfigureTestRestTemplate
class PasswordResetIntegrationTest {

    private static final String SERVICE_TOKEN =
            "test-only-authentication-service-token-32-bytes";
    private static final String ENVIRONMENT_DATA_TOKEN =
            "test-only-environment-data-token-32-bytes";
    private static final String ORIGINAL_PASSWORD =
            "A secure original password 2026!";
    private static final String NEW_PASSWORD =
            "A secure replacement password 2026!";

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private FixtureAccountEmailSender fixtureEmails;

    @Autowired
    private PasswordResetTokenRepository tokenRepository;

    @BeforeEach
    void clearFixtureMessages() {
        fixtureEmails.clear();
    }

    @Test
    void knownAndUnknownAccountsReceiveTheSameVisibleResponse() {
        String known = uniqueEmail("enumeration-known");
        register(known);

        ResponseEntity<Map> knownResponse = requestReset(known);
        ResponseEntity<Map> unknownResponse = requestReset(uniqueEmail("enumeration-unknown"));

        assertEquals(HttpStatus.ACCEPTED, knownResponse.getStatusCode());
        assertEquals(HttpStatus.ACCEPTED, unknownResponse.getStatusCode());
        assertEquals(knownResponse.getBody(), unknownResponse.getBody());
        assertTrue(fixtureEmails.latest(known, FixtureAccountEmailSender.PASSWORD_RESET).isPresent());
        assertTrue(fixtureEmails.latest(
                uniqueEmail("never-created"), FixtureAccountEmailSender.PASSWORD_RESET).isEmpty());
    }

    @Test
    void fixtureEndpointReturnsResetLinkOnlyThroughEnvironmentDataIdentity() {
        String email = uniqueEmail("fixture");
        register(email);
        requestReset(email);

        HttpHeaders environmentHeaders = new HttpHeaders();
        environmentHeaders.set("X-Environment-Data-Token", ENVIRONMENT_DATA_TOKEN);
        ResponseEntity<Map> fixture = restTemplate.exchange(
                "/internal/system-data/account-email/latest?recipient=" + email
                        + "&purpose=PASSWORD_RESET",
                HttpMethod.GET,
                new HttpEntity<>(environmentHeaders),
                Map.class);

        assertEquals(HttpStatus.OK, fixture.getStatusCode());
        assertEquals("PASSWORD_RESET", fixture.getBody().get("purpose"));
        assertTrue(fixture.getBody().get("actionUrl").toString()
                .startsWith("http://localhost:4200/reset-password#token="));

        ResponseEntity<Map> wrongIdentity = exchange(
                "/internal/system-data/account-email/latest?recipient=" + email
                        + "&purpose=PASSWORD_RESET",
                HttpMethod.GET,
                null,
                Map.class);
        assertEquals(HttpStatus.UNAUTHORIZED, wrongIdentity.getStatusCode());
    }

    @Test
    void storesOnlyDigestAndANewerRequestInvalidatesTheOlderToken() {
        String email = uniqueEmail("replacement");
        register(email);

        requestReset(email);
        String older = latestRawToken(email);
        requestReset(email);
        String newer = latestRawToken(email);

        assertNotEquals(older, newer);
        List<PasswordResetToken> records = tokenRepository.findAll();
        assertTrue(records.stream().noneMatch(token -> token.getTokenHash().equals(older)));
        assertTrue(records.stream().noneMatch(token -> token.getTokenHash().contains(older)));
        assertTrue(records.stream().allMatch(token -> token.getTokenHash().length() == 64));

        assertEquals(HttpStatus.BAD_REQUEST,
                complete(older, NEW_PASSWORD).getStatusCode());
        assertEquals(HttpStatus.OK,
                complete(newer, NEW_PASSWORD).getStatusCode());
    }

    @Test
    void expiredModifiedAndConsumedTokensFailSafely() {
        String expiredEmail = uniqueEmail("expired");
        register(expiredEmail);
        requestReset(expiredEmail);
        String expired = latestRawToken(expiredEmail);
        PasswordResetToken stored = tokenRepository
                .findTopByUserIdOrderByCreatedAtDesc(userIdFor(expiredEmail))
                .orElseThrow();
        stored.setExpiresAt(Instant.now().minusSeconds(1));
        tokenRepository.saveAndFlush(stored);

        ResponseEntity<Map> expiredResponse = complete(expired, NEW_PASSWORD);
        ResponseEntity<Map> modifiedResponse = complete(
                expired.substring(0, expired.length() - 1)
                        + (expired.endsWith("A") ? "B" : "A"),
                NEW_PASSWORD);

        String replayEmail = uniqueEmail("replay");
        register(replayEmail);
        requestReset(replayEmail);
        String consumed = latestRawToken(replayEmail);
        assertEquals(HttpStatus.OK, complete(consumed, NEW_PASSWORD).getStatusCode());
        ResponseEntity<Map> replayResponse = complete(
                consumed, "Another secure replacement password 2026!");

        assertSafeInvalid(expiredResponse);
        assertSafeInvalid(modifiedResponse);
        assertSafeInvalid(replayResponse);
    }

    @Test
    void concurrentUseSucceedsExactlyOnce() throws Exception {
        String email = uniqueEmail("concurrent");
        register(email);
        requestReset(email);
        String rawToken = latestRawToken(email);
        CountDownLatch start = new CountDownLatch(1);

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            List<Future<ResponseEntity<Map>>> futures = new ArrayList<>();
            for (int index = 0; index < 2; index++) {
                futures.add(executor.submit(() -> {
                    start.await();
                    return complete(rawToken, NEW_PASSWORD);
                }));
            }
            start.countDown();
            List<HttpStatus> statuses = futures.stream()
                    .map(this::get)
                    .map(response -> (HttpStatus) response.getStatusCode())
                    .sorted()
                    .toList();

            assertEquals(1, statuses.stream().filter(HttpStatus.OK::equals).count());
            assertEquals(1, statuses.stream().filter(HttpStatus.BAD_REQUEST::equals).count());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void malformedEmailAndPasswordPolicyFailuresAreSafeAndDoNotConsumeToken() {
        ResponseEntity<Map> malformed = requestReset("not-an-email");
        assertEquals(HttpStatus.BAD_REQUEST, malformed.getStatusCode());
        assertFalse(malformed.getBody().toString().contains("not-an-email"));

        String email = uniqueEmail("policy");
        register(email);
        requestReset(email);
        String rawToken = latestRawToken(email);

        ResponseEntity<Map> tooShort = complete(rawToken, "too short");
        assertEquals(HttpStatus.BAD_REQUEST, tooShort.getStatusCode());
        assertFalse(tooShort.getBody().toString().contains(rawToken));

        ResponseEntity<Map> accountBased = complete(rawToken, email);
        assertEquals(HttpStatus.BAD_REQUEST, accountBased.getStatusCode());
        assertFalse(accountBased.getBody().toString().contains(rawToken));

        assertEquals(HttpStatus.OK, complete(rawToken, NEW_PASSWORD).getStatusCode());
        assertEquals(HttpStatus.OK, login(email, NEW_PASSWORD).getStatusCode());
    }

    @Test
    void successfulResetRevokesAllSessionsRejectsReuseAndSendsNotification() {
        String email = uniqueEmail("sessions");
        register(email);
        Map firstSession = login(email, ORIGINAL_PASSWORD).getBody();
        Map secondSession = login(email, ORIGINAL_PASSWORD).getBody();
        assertNotNull(firstSession);
        assertNotNull(secondSession);

        requestReset(email);
        String rawToken = latestRawToken(email);
        assertEquals(HttpStatus.BAD_REQUEST,
                complete(rawToken, ORIGINAL_PASSWORD).getStatusCode());
        assertEquals(HttpStatus.OK,
                complete(rawToken, NEW_PASSWORD).getStatusCode());

        assertEquals(HttpStatus.UNAUTHORIZED,
                me(firstSession.get("token").toString()).getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED,
                me(secondSession.get("token").toString()).getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED,
                refresh(firstSession.get("refreshToken").toString()).getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED,
                refresh(secondSession.get("refreshToken").toString()).getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED,
                login(email, ORIGINAL_PASSWORD).getStatusCode());
        assertEquals(HttpStatus.OK, login(email, NEW_PASSWORD).getStatusCode());
        assertTrue(fixtureEmails.latest(
                email, FixtureAccountEmailSender.PASSWORD_CHANGED).isPresent());
    }

    private void register(String email) {
        ResponseEntity<Map> response = exchange(
                "/api/auth/register", HttpMethod.POST,
                new RegisterRequest("Reset Test User", email, ORIGINAL_PASSWORD), Map.class);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
    }

    private ResponseEntity<Map> requestReset(String email) {
        return exchange("/api/auth/password-reset/request", HttpMethod.POST,
                new PasswordResetRequest(email), Map.class);
    }

    private ResponseEntity<Map> complete(String token, String password) {
        return exchange("/api/auth/password-reset/complete", HttpMethod.POST,
                new PasswordResetCompletionRequest(token, password), Map.class);
    }

    private ResponseEntity<Map> login(String email, String password) {
        return exchange("/api/auth/login", HttpMethod.POST,
                new LoginRequest(email, password), Map.class);
    }

    private ResponseEntity<Map> refresh(String refreshToken) {
        return exchange("/api/auth/refresh", HttpMethod.POST,
                Map.of("refreshToken", refreshToken), Map.class);
    }

    private ResponseEntity<Map> me(String token) {
        HttpHeaders headers = serviceHeaders();
        headers.setBearerAuth(token);
        return restTemplate.exchange(
                "/api/auth/me", HttpMethod.GET, new HttpEntity<>(headers), Map.class);
    }

    private String latestRawToken(String email) {
        URI actionUrl = fixtureEmails
                .latest(email, FixtureAccountEmailSender.PASSWORD_RESET)
                .orElseThrow()
                .actionUrl();
        String fragment = actionUrl.getRawFragment();
        assertTrue(fragment.startsWith("token="));
        return fragment.substring("token=".length());
    }

    private String userIdFor(String email) {
        ResponseEntity<Map> login = login(email, ORIGINAL_PASSWORD);
        String token = login.getBody().get("token").toString();
        ResponseEntity<Map> me = me(token);
        return me.getBody().get("id").toString();
    }

    private void assertSafeInvalid(ResponseEntity<Map> response) {
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("PASSWORD_RESET_LINK_INVALID", response.getBody().get("code"));
        assertEquals("This password-reset link is invalid or has expired.",
                response.getBody().get("message"));
        assertFalse(response.getBody().toString().contains("token"));
    }

    private <T> ResponseEntity<T> exchange(
            String path, HttpMethod method, Object body, Class<T> responseType) {
        return restTemplate.exchange(
                path, method, new HttpEntity<>(body, serviceHeaders()), responseType);
    }

    private HttpHeaders serviceHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Service-Token", SERVICE_TOKEN);
        return headers;
    }

    private ResponseEntity<Map> get(Future<ResponseEntity<Map>> future) {
        try {
            return future.get();
        } catch (Exception exception) {
            throw new AssertionError(exception);
        }
    }

    private String uniqueEmail(String prefix) {
        return prefix + "-" + System.nanoTime() + "@example.test";
    }
}
