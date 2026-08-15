package com.jobseekercopilot.authenticationservice;

import com.jobseekercopilot.authenticationservice.model.LoginRequest;
import com.jobseekercopilot.authenticationservice.model.RegisterRequest;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "auth.login.maximum-failures=3",
        "auth.login.attempt-window=15m",
        "auth.login.lock-duration=15m",
        "environment-data.enabled=true"
})
@AutoConfigureTestRestTemplate
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthenticationServiceIntegrationTest {

    private static final String SERVICE_TOKEN = "test-only-authentication-service-token-32-bytes";
    private static final String ENVIRONMENT_DATA_TOKEN = "test-only-environment-data-token-32-bytes";

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ApplicationContext applicationContext;

    @BeforeAll
    void authenticateServiceClient() {
        restTemplate.getRestTemplate().getInterceptors().add((request, body, execution) -> {
            request.getHeaders().set("X-Service-Token", SERVICE_TOKEN);
            return execution.execute(request, body);
        });
    }

    @Test
    void serviceIdentityIsRequiredAndNeverReflected() {
        TestRestTemplate unauthenticated = new TestRestTemplate();
        ResponseEntity<Map> missing = unauthenticated.postForEntity(
                url("/api/auth/login"), new LoginRequest("nobody@example.test", "not-a-password"), Map.class);

        HttpHeaders invalidHeaders = new HttpHeaders();
        invalidHeaders.setContentType(MediaType.APPLICATION_JSON);
        invalidHeaders.set("X-Service-Token", "attacker-controlled-value");
        ResponseEntity<Map> invalid = unauthenticated.exchange(
                url("/api/auth/login"), HttpMethod.POST,
                new HttpEntity<>(new LoginRequest("nobody@example.test", "not-a-password"), invalidHeaders),
                Map.class);

        assertEquals(HttpStatus.UNAUTHORIZED, missing.getStatusCode());
        assertEquals("SERVICE_AUTHENTICATION_REQUIRED", missing.getBody().get("code"));
        assertEquals(HttpStatus.UNAUTHORIZED, invalid.getStatusCode());
        assertEquals(missing.getBody().get("message"), invalid.getBody().get("message"));
        assertFalse(invalid.getBody().toString().contains("attacker-controlled-value"));
        assertNotNull(missing.getHeaders().getFirst("X-Correlation-Id"));
        assertEquals("nosniff", missing.getHeaders().getFirst("X-Content-Type-Options"));
        assertEquals("DENY", missing.getHeaders().getFirst("X-Frame-Options"));
        assertTrue(missing.getHeaders().getFirst("Cache-Control").contains("no-store"));
    }

    @Test
    void browserCorsPreflightIsNotTrusted() {
        TestRestTemplate unauthenticated = new TestRestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setOrigin("https://untrusted.example");
        headers.set("Access-Control-Request-Method", "POST");

        ResponseEntity<Map> response = unauthenticated.exchange(
                url("/api/auth/login"), HttpMethod.OPTIONS, new HttpEntity<>(headers), Map.class);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertFalse(response.getHeaders().containsHeader("Access-Control-Allow-Origin"));
    }

    @Test
    void defaultUserAndBrowserAuthenticationEntryPointsAreAbsent() {
        assertTrue(applicationContext.getBeansOfType(UserDetailsService.class).isEmpty());

        TestRestTemplate unauthenticated = new TestRestTemplate();
        HttpHeaders basicHeaders = new HttpHeaders();
        basicHeaders.setBasicAuth("unused", "not-a-credential");
        ResponseEntity<Map> basic = unauthenticated.exchange(
                url("/api/auth/me"), HttpMethod.GET, new HttpEntity<>(basicHeaders), Map.class);

        HttpHeaders formHeaders = new HttpHeaders();
        formHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        ResponseEntity<Map> form = unauthenticated.exchange(
                url("/login"), HttpMethod.POST,
                new HttpEntity<>("username=unused&password=not-a-credential", formHeaders), Map.class);

        assertEquals(HttpStatus.UNAUTHORIZED, basic.getStatusCode());
        assertEquals("SERVICE_AUTHENTICATION_REQUIRED", basic.getBody().get("code"));
        assertFalse(basic.getHeaders().containsHeader(HttpHeaders.WWW_AUTHENTICATE));
        assertEquals(HttpStatus.UNAUTHORIZED, form.getStatusCode());
        assertEquals("SERVICE_AUTHENTICATION_REQUIRED", form.getBody().get("code"));
        assertFalse(form.getHeaders().containsHeader(HttpHeaders.LOCATION));
        assertFalse(form.getHeaders().containsHeader(HttpHeaders.SET_COOKIE));
    }

    @Test
    void healthIsPublicButUnknownAndDocumentationRoutesAreDenied() {
        TestRestTemplate unauthenticated = new TestRestTemplate();

        assertEquals(HttpStatus.OK,
                unauthenticated.getForEntity(url("/actuator/health"), Map.class).getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED,
                unauthenticated.getForEntity(url("/not-an-application-route"), Map.class).getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED,
                unauthenticated.getForEntity(url("/v3/api-docs"), String.class).getStatusCode());
    }

    @Test
    void environmentDataRequiresItsSeparateIdentity() {
        TestRestTemplate client = new TestRestTemplate();
        HttpHeaders serviceHeaders = new HttpHeaders();
        serviceHeaders.set("X-Service-Token", SERVICE_TOKEN);
        HttpHeaders environmentHeaders = new HttpHeaders();
        environmentHeaders.set("X-Environment-Data-Token", ENVIRONMENT_DATA_TOKEN);

        ResponseEntity<Map> serviceIdentity = client.exchange(
                url("/internal/system-data/verify/users/absent"), HttpMethod.GET,
                new HttpEntity<>(serviceHeaders), Map.class);
        ResponseEntity<Map> environmentIdentity = client.exchange(
                url("/internal/system-data/verify/users/absent"), HttpMethod.GET,
                new HttpEntity<>(environmentHeaders), Map.class);
        ResponseEntity<Map> wrongBoundary = client.exchange(
                url("/api/auth/me"), HttpMethod.GET,
                new HttpEntity<>(environmentHeaders), Map.class);

        assertEquals(HttpStatus.UNAUTHORIZED, serviceIdentity.getStatusCode());
        assertEquals(HttpStatus.OK, environmentIdentity.getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED, wrongBoundary.getStatusCode());
    }

    @Test
    void register_Login_And_GetUser_HappyPath() {
        // Register
        RegisterRequest registerRequest = acceptedRegistration(
                "John Doe", "john@test.com", "A memorable local passphrase 2026!");
        ResponseEntity<Map> registerResponse = restTemplate.postForEntity(
                "/api/auth/register", registerRequest, Map.class);

        assertEquals(HttpStatus.CREATED, registerResponse.getStatusCode());
        assertEquals("User registered successfully.", registerResponse.getBody().get("message"));

        // Login
        LoginRequest loginRequest = new LoginRequest("john@test.com", "A memorable local passphrase 2026!");
        ResponseEntity<Map> loginResponse = restTemplate.postForEntity(
                "/api/auth/login", loginRequest, Map.class);

        assertEquals(HttpStatus.OK, loginResponse.getStatusCode());
        assertNotNull(loginResponse.getBody().get("token"));

        // Get current user with token
        String token = (String) loginResponse.getBody().get("token");

        var headers = new org.springframework.http.HttpHeaders();
        headers.set("Authorization", "Bearer " + token);
        var requestEntity = new org.springframework.http.HttpEntity<>(headers);
        ResponseEntity<Map> meEntity = restTemplate.exchange(
                "/api/auth/me",
                org.springframework.http.HttpMethod.GET,
                requestEntity,
                Map.class);

        assertEquals(HttpStatus.OK, meEntity.getStatusCode());
        assertEquals("john@test.com", meEntity.getBody().get("email"));
        assertEquals("John Doe", meEntity.getBody().get("name"));
    }

    @Test
    void registrationRequiresExplicitCurrentLegalAcceptance() {
        RegisterRequest missingAge = new RegisterRequest(
                "Missing Age", "missing-age@example.test",
                "A legally reviewed passphrase 2026!",
                true, true, false, "2026-08-15");
        RegisterRequest staleVersion = new RegisterRequest(
                "Stale Legal", "stale-legal@example.test",
                "Another legally reviewed passphrase 2026!",
                true, true, true, "2026-07-01");

        ResponseEntity<Map> missing = restTemplate.postForEntity(
                "/api/auth/register", missingAge, Map.class);
        ResponseEntity<Map> stale = restTemplate.postForEntity(
                "/api/auth/register", staleVersion, Map.class);

        assertEquals(HttpStatus.BAD_REQUEST, missing.getStatusCode());
        assertEquals("LEGAL_ACCEPTANCE_REQUIRED", missing.getBody().get("code"));
        assertEquals(HttpStatus.CONFLICT, stale.getStatusCode());
        assertEquals("LEGAL_VERSION_OUTDATED", stale.getBody().get("code"));
        assertEquals(
                HttpStatus.UNAUTHORIZED,
                login("missing-age@example.test", "A legally reviewed passphrase 2026!")
                        .getStatusCode());
        assertEquals(
                HttpStatus.UNAUTHORIZED,
                login("stale-legal@example.test", "Another legally reviewed passphrase 2026!")
                        .getStatusCode());
    }

    @Test
    void canonicalEmailVariantsShareOneAccountWhileDisplayAddressIsPreserved() {
        String password = "A canonical identity passphrase 2026!";
        ResponseEntity<Map> registration = restTemplate.postForEntity(
                "/api/auth/register",
                acceptedRegistration("Canonical User", "\u00a0Case.User@Example.Test\u2003", password),
                Map.class);
        ResponseEntity<Map> duplicate = restTemplate.postForEntity(
                "/api/auth/register",
                acceptedRegistration("Duplicate User", "case.user@example.test", password),
                Map.class);
        ResponseEntity<Map> login = restTemplate.postForEntity(
                "/api/auth/login",
                new LoginRequest("CASE.USER@EXAMPLE.TEST", password),
                Map.class);

        assertEquals(HttpStatus.CREATED, registration.getStatusCode());
        assertEquals(HttpStatus.CONFLICT, duplicate.getStatusCode());
        assertEquals(HttpStatus.OK, login.getStatusCode());

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth((String) login.getBody().get("token"));
        ResponseEntity<Map> account = restTemplate.exchange(
                "/api/auth/me", HttpMethod.GET, new HttpEntity<>(headers), Map.class);

        assertEquals(HttpStatus.OK, account.getStatusCode());
        assertEquals("Case.User@Example.Test", account.getBody().get("email"));
    }

    @Test
    void registrationRejectsWeakAndCompromisedPasswords() {
        ResponseEntity<Map> shortResponse = restTemplate.postForEntity(
                "/api/auth/register",
                new RegisterRequest("Weak User", "weak@example.test", "too-short"),
                Map.class);
        ResponseEntity<Map> compromisedResponse = restTemplate.postForEntity(
                "/api/auth/register",
                new RegisterRequest("Common User", "common@example.test", "CORRECT HORSE BATTERY STAPLE"),
                Map.class);

        assertEquals(HttpStatus.BAD_REQUEST, shortResponse.getStatusCode());
        assertEquals(HttpStatus.BAD_REQUEST, compromisedResponse.getStatusCode());
    }

    @Test
    void unknownAccountAndWrongPasswordReturnUniformFailure() {
        String email = "uniform@example.test";
        restTemplate.postForEntity(
                "/api/auth/register",
                acceptedRegistration("Uniform User", email, "A unique uniform passphrase 2026!"),
                Map.class);

        ResponseEntity<Map> wrongPassword = restTemplate.postForEntity(
                "/api/auth/login", new LoginRequest(email, "wrong-password"), Map.class);
        ResponseEntity<Map> unknownAccount = restTemplate.postForEntity(
                "/api/auth/login", new LoginRequest("unknown-uniform@example.test", "wrong-password"), Map.class);

        assertEquals(HttpStatus.UNAUTHORIZED, wrongPassword.getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED, unknownAccount.getStatusCode());
        assertEquals("Invalid email or password.", wrongPassword.getBody().get("message"));
        assertEquals(wrongPassword.getBody().get("message"), unknownAccount.getBody().get("message"));
    }

    @Test
    void repeatedFailuresAreRateLimitedWithRecoveryHint() {
        String email = "rate-limit@example.test";
        restTemplate.postForEntity(
                "/api/auth/register",
                acceptedRegistration("Rate Limit User", email, "A unique rate limit passphrase 2026!"),
                Map.class);

        ResponseEntity<Map> first = login(email, "wrong-password");
        ResponseEntity<Map> second = login(email, "wrong-password");
        ResponseEntity<Map> threshold = login(email, "wrong-password");

        assertEquals(HttpStatus.UNAUTHORIZED, first.getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED, second.getStatusCode());
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, threshold.getStatusCode());
        assertEquals("Too many authentication attempts. Try again later.", threshold.getBody().get("message"));
        assertNotNull(threshold.getHeaders().getFirst("Retry-After"));
    }

    @Test
    void missingTokenReturnsVersionedCorrelatedError() {
        String correlationId = "auth-07-missing-token";
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Correlation-Id", correlationId);

        ResponseEntity<Map> response = restTemplate.exchange(
                "/api/auth/me", HttpMethod.GET, new HttpEntity<>(headers), Map.class);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("1", response.getBody().get("schemaVersion"));
        assertEquals("TOKEN_REQUIRED", response.getBody().get("code"));
        assertEquals("A Bearer token is required.", response.getBody().get("message"));
        assertEquals(correlationId, response.getBody().get("correlationId"));
        assertEquals(correlationId, response.getHeaders().getFirst("X-Correlation-Id"));
    }

    @Test
    void malformedJsonReturnsStableBadRequestWithoutParserDetails() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<Map> response = restTemplate.exchange(
                "/api/auth/login", HttpMethod.POST,
                new HttpEntity<>("{not-json", headers), Map.class);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("MALFORMED_JSON", response.getBody().get("code"));
        assertEquals("Request body is not valid JSON.", response.getBody().get("message"));
        assertFalse(response.getBody().toString().contains("JsonParseException"));
        assertFalse(response.getBody().toString().contains("not-json"));
    }

    @Test
    void expiredTokenReturnsStableUnauthorizedErrorWithoutParserDetails() {
        Date now = new Date();
        String token = Jwts.builder()
                .header().keyId("test-key").and()
                .issuer("test-issuer")
                .audience().add("test-audience").and()
                .subject("expired-user")
                .id("expired-token-id")
                .claim("sid", "expired-session")
                .claim("token_type", "access")
                .issuedAt(new Date(now.getTime() - 120_000))
                .expiration(new Date(now.getTime() - 60_000))
                .signWith(TestJwtKeys.ACTIVE.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertTokenFailure(token, "TOKEN_EXPIRED", "The authentication token has expired.");
    }

    @Test
    void malformedTokenReturnsStableUnauthorizedErrorWithoutParserDetails() {
        assertTokenFailure("not-a-jwt", "TOKEN_MALFORMED", "The authentication token is malformed.");
    }

    @Test
    void unsupportedUnsignedTokenReturnsStableUnauthorizedErrorWithoutParserDetails() {
        String token = Jwts.builder().subject("unsupported-user").compact();

        assertTokenFailure(token, "TOKEN_UNSUPPORTED", "The authentication token is unsupported.");
    }

    @Test
    void differentlySignedTokenReturnsStableUnauthorizedError() {
        String token = Jwts.builder()
                .header().keyId("different-key").and()
                .subject("other-key-user")
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(TestJwtKeys.DIFFERENT.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertTokenFailure(token, "TOKEN_INVALID", "The authentication token is invalid.");
    }

    @Test
    void jwksIsPublicCacheableAndContainsNoPrivateMaterial() {
        TestRestTemplate unauthenticated = new TestRestTemplate();
        ResponseEntity<Map> response = unauthenticated.getForEntity(url("/.well-known/jwks.json"), Map.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getHeaders().getCacheControl().contains("max-age=300"));
        assertTrue(response.getHeaders().getCacheControl().contains("public"));
        assertFalse(response.getBody().toString().contains("\"d\""));
        assertTrue(response.getBody().toString().contains(TestJwtKeys.ACTIVE_KEY_ID));
    }

    @Test
    void refreshRotatesOnceAndReplayRevokesTheCompleteSession() {
        String email = "refresh-session@example.test";
        String password = "A refresh session passphrase 2026!";
        restTemplate.postForEntity("/api/auth/register",
                acceptedRegistration("Refresh User", email, password), Map.class);
        ResponseEntity<Map> login = login(email, password);
        String firstAccess = (String) login.getBody().get("token");
        String firstRefresh = (String) login.getBody().get("refreshToken");

        ResponseEntity<Map> rotated = restTemplate.postForEntity(
                "/api/auth/refresh", Map.of("refreshToken", firstRefresh), Map.class);
        assertEquals(HttpStatus.OK, rotated.getStatusCode());
        assertNotEquals(firstAccess, rotated.getBody().get("token"));
        assertNotEquals(firstRefresh, rotated.getBody().get("refreshToken"));
        assertEquals("Bearer", rotated.getBody().get("tokenType"));
        assertEquals(900, rotated.getBody().get("expiresIn"));

        ResponseEntity<Map> replay = restTemplate.postForEntity(
                "/api/auth/refresh", Map.of("refreshToken", firstRefresh), Map.class);
        assertEquals(HttpStatus.UNAUTHORIZED, replay.getStatusCode());
        assertEquals("REFRESH_TOKEN_REUSED", replay.getBody().get("code"));
        assertFalse(replay.getBody().toString().contains(firstRefresh));

        assertTokenFailure((String) rotated.getBody().get("token"),
                "TOKEN_INVALID", "The authentication token is invalid.");
        ResponseEntity<Map> revokedRefresh = restTemplate.postForEntity(
                "/api/auth/refresh",
                Map.of("refreshToken", rotated.getBody().get("refreshToken")), Map.class);
        assertEquals(HttpStatus.UNAUTHORIZED, revokedRefresh.getStatusCode());
        assertEquals("REFRESH_TOKEN_INVALID", revokedRefresh.getBody().get("code"));
    }

    @Test
    void logoutImmediatelyInvalidatesTheCurrentAccessAndRefreshTokens() {
        String email = "logout-session@example.test";
        String password = "A logout session passphrase 2026!";
        restTemplate.postForEntity("/api/auth/register",
                acceptedRegistration("Logout User", email, password), Map.class);
        ResponseEntity<Map> login = login(email, password);
        String access = (String) login.getBody().get("token");

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(access);
        ResponseEntity<Void> logout = restTemplate.exchange(
                "/api/auth/logout", HttpMethod.POST, new HttpEntity<>(headers), Void.class);
        assertEquals(HttpStatus.NO_CONTENT, logout.getStatusCode());

        assertTokenFailure(access, "TOKEN_INVALID", "The authentication token is invalid.");
        ResponseEntity<Map> refresh = restTemplate.postForEntity(
                "/api/auth/refresh",
                Map.of("refreshToken", login.getBody().get("refreshToken")), Map.class);
        assertEquals(HttpStatus.UNAUTHORIZED, refresh.getStatusCode());
        assertEquals("REFRESH_TOKEN_INVALID", refresh.getBody().get("code"));
    }

    private void assertTokenFailure(String token, String expectedCode, String expectedMessage) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        ResponseEntity<Map> response = restTemplate.exchange(
                "/api/auth/me", HttpMethod.GET, new HttpEntity<>(headers), Map.class);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(expectedCode, response.getBody().get("code"));
        assertEquals(expectedMessage, response.getBody().get("message"));
        assertNotNull(response.getBody().get("correlationId"));
        assertFalse(response.getBody().toString().contains(token));
        assertFalse(response.getBody().toString().contains("io.jsonwebtoken"));
    }

    private ResponseEntity<Map> login(String email, String password) {
        return restTemplate.postForEntity("/api/auth/login", new LoginRequest(email, password), Map.class);
    }

    private RegisterRequest acceptedRegistration(
            String name, String email, String password) {
        return new RegisterRequest(
                name, email, password, true, true, true, "2026-08-15");
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }
}
