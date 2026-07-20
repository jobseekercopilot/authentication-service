package com.jobseekercopilot.authenticationservice;

import com.jobseekercopilot.authenticationservice.model.LoginRequest;
import com.jobseekercopilot.authenticationservice.model.RegisterRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "auth.login.maximum-failures=3",
        "auth.login.attempt-window=15m",
        "auth.login.lock-duration=15m"
})
@AutoConfigureTestRestTemplate
class AuthenticationServiceIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void register_Login_And_GetUser_HappyPath() {
        // Register
        RegisterRequest registerRequest = new RegisterRequest(
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
                new RegisterRequest("Uniform User", email, "A unique uniform passphrase 2026!"),
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
                new RegisterRequest("Rate Limit User", email, "A unique rate limit passphrase 2026!"),
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

    private ResponseEntity<Map> login(String email, String password) {
        return restTemplate.postForEntity("/api/auth/login", new LoginRequest(email, password), Map.class);
    }
}
