package com.jobseekercopilot.authenticationservice.contract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class OpenApiExportTest {

    private static final Path TRACKED_CONTRACT = Path.of("contracts", "openapi.json");
    private static final Path GENERATED_CONTRACT = Path.of("target", "openapi.json");
    private static final String UPDATE_PROPERTY = "authentication.updateContract";
    private static final String SERVICE_TOKEN =
            "test-only-authentication-service-token-32-bytes";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Test
    void runtimeContractMatchesTheTrackedContract() throws Exception {
        String response = mockMvc.perform(get("/v3/api-docs")
                        .header("X-Service-Token", SERVICE_TOKEN))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode runtimeContract = OBJECT_MAPPER.readTree(response);
        assertTrue(runtimeContract.path("paths").has("/api/auth/me"));
        assertTrue(runtimeContract.path("paths").fieldNames().hasNext());
        runtimeContract.path("paths").fieldNames().forEachRemaining(
                path -> assertTrue(!path.startsWith("/internal/"),
                        () -> "Internal route leaked into the public contract: " + path));

        Files.createDirectories(GENERATED_CONTRACT.getParent());
        String formatted = OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
                .writeValueAsString(runtimeContract) + System.lineSeparator();
        Files.writeString(GENERATED_CONTRACT, formatted, StandardCharsets.UTF_8);

        if (Boolean.getBoolean(UPDATE_PROPERTY)) {
            Files.createDirectories(TRACKED_CONTRACT.getParent());
            Files.writeString(TRACKED_CONTRACT, formatted, StandardCharsets.UTF_8);
        } else {
            assertTrue(Files.isRegularFile(TRACKED_CONTRACT),
                    "Tracked contract is missing. Regenerate intentionally with -D"
                            + UPDATE_PROPERTY + "=true.");
            assertEquals(
                    OBJECT_MAPPER.readTree(Files.readString(TRACKED_CONTRACT)),
                    runtimeContract,
                    "Runtime OpenAPI drifted from contracts/openapi.json. "
                            + "Review and regenerate the contract intentionally.");
        }
    }
}
