package com.jobseekercopilot.authenticationservice.contract;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class OpenApiContractPolicyTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Path CONTRACT = Path.of("contracts", "openapi.json");
    private static final Path CHECKSUMS = Path.of("contracts", "SHA256SUMS");

    @Test
    void trackedContractSatisfiesTheDownstreamBoundaryPolicy() throws Exception {
        byte[] bytes = Files.readAllBytes(CONTRACT);
        assertTrue(violations(OBJECT_MAPPER.readTree(bytes), bytes, trackedChecksum()).isEmpty());
    }

    @Test
    void missingContractIsRejected() throws Exception {
        assertViolation(violations(null, null, trackedChecksum()), "contract is missing");
    }

    @Test
    void checksumDriftIsRejected() throws Exception {
        byte[] drifted = (Files.readString(CONTRACT) + " ").getBytes(StandardCharsets.UTF_8);
        assertViolation(
                violations(OBJECT_MAPPER.readTree(drifted), drifted, trackedChecksum()),
                "checksum does not match");
    }

    @Test
    void operationRemovalIsRejected() throws Exception {
        ObjectNode changed = contract().deepCopy();
        ((ObjectNode) changed.path("paths")).remove("/api/auth/me");
        assertViolation(violations(changed, null, null), "getCurrentUser operation is missing");
    }

    @Test
    void responseFieldRemovalIsRejected() throws Exception {
        ObjectNode changed = contract().deepCopy();
        ((ObjectNode) changed.at("/components/schemas/UserAccountResponse/properties")).remove("email");
        assertViolation(violations(changed, null, null), "response field is missing: email");
    }

    @Test
    void securityWeakeningIsRejected() throws Exception {
        ObjectNode changed = contract().deepCopy();
        ArrayNode weakened = OBJECT_MAPPER.createArrayNode()
                .add(OBJECT_MAPPER.createObjectNode().set("bearerAuth", OBJECT_MAPPER.createArrayNode()))
                .add(OBJECT_MAPPER.createObjectNode().set("serviceToken", OBJECT_MAPPER.createArrayNode()));
        ((ObjectNode) changed.at("/paths/~1api~1auth~1me/get")).set("security", weakened);
        assertViolation(
                violations(changed, null, null),
                "bearerAuth and serviceToken must be required together");
    }

    private static ObjectNode contract() throws Exception {
        return (ObjectNode) OBJECT_MAPPER.readTree(Files.readAllBytes(CONTRACT));
    }

    private static String trackedChecksum() throws Exception {
        String line = Files.readString(CHECKSUMS).strip();
        assertTrue(line.endsWith("  openapi.json"), "SHA256SUMS must identify openapi.json");
        return line.split("\\s+")[0];
    }

    private static List<String> violations(JsonNode contract, byte[] bytes, String expectedChecksum)
            throws Exception {
        List<String> failures = new ArrayList<>();
        if (contract == null || contract.isMissingNode()) {
            failures.add("contract is missing");
            return failures;
        }

        if (bytes != null && expectedChecksum != null) {
            String actual = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(bytes));
            if (!actual.equals(expectedChecksum)) {
                failures.add("checksum does not match");
            }
        }

        JsonNode operation = contract.at("/paths/~1api~1auth~1me/get");
        if (operation.isMissingNode()
                || !"getCurrentUser".equals(operation.path("operationId").asText())) {
            failures.add("getCurrentUser operation is missing");
        }

        JsonNode security = operation.path("security");
        boolean requiresBoth = security.isArray()
                && security.size() == 1
                && security.get(0).isObject()
                && Set.copyOf(iterableFieldNames(security.get(0)))
                        .equals(Set.of("bearerAuth", "serviceToken"));
        if (!requiresBoth) {
            failures.add("bearerAuth and serviceToken must be required together");
        }

        JsonNode bearer = contract.at("/components/securitySchemes/bearerAuth");
        if (!"http".equals(bearer.path("type").asText())
                || !"bearer".equals(bearer.path("scheme").asText())) {
            failures.add("bearerAuth security scheme is missing");
        }
        JsonNode service = contract.at("/components/securitySchemes/serviceToken");
        if (!"apiKey".equals(service.path("type").asText())
                || !"header".equals(service.path("in").asText())
                || !"X-Service-Token".equals(service.path("name").asText())) {
            failures.add("serviceToken security scheme is missing");
        }

        JsonNode properties = contract.at("/components/schemas/UserAccountResponse/properties");
        for (String field : List.of("id", "name", "email")) {
            if (!properties.has(field)) {
                failures.add("response field is missing: " + field);
            }
        }

        contract.path("paths").fieldNames().forEachRemaining(path -> {
            if (path.startsWith("/internal/")) {
                failures.add("internal route is exposed: " + path);
            }
        });
        return failures;
    }

    private static List<String> iterableFieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private static void assertViolation(List<String> violations, String expected) {
        assertTrue(violations.contains(expected), () -> "Expected '" + expected + "' in " + violations);
    }
}
