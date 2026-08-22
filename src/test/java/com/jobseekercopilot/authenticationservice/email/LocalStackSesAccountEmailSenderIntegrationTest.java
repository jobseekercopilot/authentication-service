package com.jobseekercopilot.authenticationservice.email;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ses.SesClient;

@EnabledIfEnvironmentVariable(
        named = "LOCALSTACK_SES_ENDPOINT",
        matches = "http://127\\.0\\.0\\.1:4566")
class LocalStackSesAccountEmailSenderIntegrationTest {

    private static final URI CAPTURE_ENDPOINT = URI.create("http://127.0.0.1:4566/_aws/ses");
    private static final String RECIPIENT = "localstack-account@example.test";
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();

    @BeforeEach
    @AfterEach
    void clearCapturedMessages() throws Exception {
        HttpResponse<Void> response = http.send(
                HttpRequest.newBuilder(CAPTURE_ENDPOINT).DELETE().build(),
                HttpResponse.BodyHandlers.discarding());
        assertTrue(response.statusCode() == 200 || response.statusCode() == 204,
                "LocalStack SES cleanup must succeed");
    }

    @Test
    void productionAdapterDeliversBothAccountEmailPurposesThroughLocalStack()
            throws Exception {
        try (SesClient client = SesClient.builder()
                .region(Region.EU_WEST_2)
                .endpointOverride(URI.create("http://127.0.0.1:4566"))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .build()) {
            SesAccountEmailSender sender = new SesAccountEmailSender(
                    client,
                    "accounts@jobseekercopilot.com",
                    "JobSeekerCopilotAccountEmails",
                    "https://jobseekercopilot.com/contact");
            URI resetLink = URI.create(
                    "https://app.jobseekercopilot.com/reset-password#token="
                            + "A".repeat(43));

            sender.sendPasswordReset(
                    "local-account", RECIPIENT, resetLink,
                    Instant.parse("2026-07-28T12:30:00Z"));
            sender.sendPasswordChanged("local-account", RECIPIENT);

            JsonNode messages = capturedMessages();
            assertEquals(2, messages.size());
            JsonNode reset = findBySubject(messages, "Reset your Job Seeker Copilot password");
            assertEquals(
                    "accounts@jobseekercopilot.com",
                    reset.path("Source").asText());
            assertEquals(
                    RECIPIENT,
                    reset.path("Destination").path("ToAddresses").path(0).asText());
            assertTrue(reset.path("Body").path("text_part").asText()
                    .contains(resetLink.toASCIIString()));
            assertTrue(reset.path("Body").path("html_part").asText()
                    .contains(resetLink.toASCIIString()));

            JsonNode changed = findBySubject(
                    messages, "Your Job Seeker Copilot password was changed");
            assertTrue(changed.path("Body").path("text_part").asText()
                    .contains("Every existing session has been signed out."));
            assertFalse(changed.path("Body").path("text_part").asText()
                    .contains("/reset-password"));
        }
    }

    private JsonNode capturedMessages() throws Exception {
        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(CAPTURE_ENDPOINT).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        return json.readTree(response.body()).path("messages");
    }

    private static JsonNode findBySubject(JsonNode messages, String subject) {
        return StreamSupport.stream(messages.spliterator(), false)
                .filter(message -> subject.equals(message.path("Subject").asText()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected account-email subject was not captured"));
    }
}
