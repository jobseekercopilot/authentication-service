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

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
class AuthenticationServiceIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void register_Login_And_GetUser_HappyPath() {
        // Register
        RegisterRequest registerRequest = new RegisterRequest("John Doe", "john@test.com", "password123");
        ResponseEntity<Map> registerResponse = restTemplate.postForEntity(
                "/api/auth/register", registerRequest, Map.class);

        assertEquals(HttpStatus.CREATED, registerResponse.getStatusCode());
        assertEquals("User registered successfully.", registerResponse.getBody().get("message"));

        // Login
        LoginRequest loginRequest = new LoginRequest("john@test.com", "password123");
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
}
