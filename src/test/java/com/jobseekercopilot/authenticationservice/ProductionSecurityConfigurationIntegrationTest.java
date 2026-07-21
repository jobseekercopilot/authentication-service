package com.jobseekercopilot.authenticationservice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@ActiveProfiles("production")
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
class ProductionSecurityConfigurationIntegrationTest {

    @Container
    private static final PostgreSQLContainer POSTGRES =
            new PostgreSQLContainer("postgres:17-alpine")
                    .withDatabaseName("authentication")
                    .withUsername("authentication")
                    .withPassword("test-only-database-password");

    @DynamicPropertySource
    static void productionDatabase(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username", POSTGRES::getUsername);
        properties.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @LocalServerPort
    private int port;

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    void productionContextHasOnlyTheExplicitServiceBoundary(CapturedOutput output) {
        assertTrue(applicationContext.getBeansOfType(UserDetailsService.class).isEmpty());
        assertFalse(output.getAll().contains("generated security " + "password"));
        assertFalse(output.getAll().contains("inMemoryUserDetailsManager"));

        TestRestTemplate client = new TestRestTemplate();
        HttpHeaders basicHeaders = new HttpHeaders();
        basicHeaders.setBasicAuth("unused", "not-a-credential");

        ResponseEntity<Map> protectedRoute = client.exchange(
                url("/api/auth/me"), HttpMethod.GET, new HttpEntity<>(basicHeaders), Map.class);
        HttpHeaders formHeaders = new HttpHeaders();
        formHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        ResponseEntity<Map> formRoute = client.exchange(
                url("/login"), HttpMethod.POST,
                new HttpEntity<>("username=unused&password=not-a-credential", formHeaders), Map.class);
        ResponseEntity<Map> health = client.getForEntity(url("/actuator/health"), Map.class);

        assertEquals(HttpStatus.UNAUTHORIZED, protectedRoute.getStatusCode());
        assertEquals("SERVICE_AUTHENTICATION_REQUIRED", protectedRoute.getBody().get("code"));
        assertFalse(protectedRoute.getHeaders().containsHeader(HttpHeaders.WWW_AUTHENTICATE));
        assertEquals(HttpStatus.UNAUTHORIZED, formRoute.getStatusCode());
        assertEquals("SERVICE_AUTHENTICATION_REQUIRED", formRoute.getBody().get("code"));
        assertFalse(formRoute.getHeaders().containsHeader(HttpHeaders.LOCATION));
        assertFalse(formRoute.getHeaders().containsHeader(HttpHeaders.SET_COOKIE));
        assertEquals(HttpStatus.OK, health.getStatusCode());
        assertEquals("UP", health.getBody().get("status"));
        assertFalse(health.getBody().containsKey("components"));
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }
}
