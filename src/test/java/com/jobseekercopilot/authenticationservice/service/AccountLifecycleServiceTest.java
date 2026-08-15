package com.jobseekercopilot.authenticationservice.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.jobseekercopilot.authenticationservice.model.RegistrationLegalAcceptanceResponse;
import com.jobseekercopilot.authenticationservice.model.UserAccountResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.databind.JsonNode;

@ExtendWith(MockitoExtension.class)
class AccountLifecycleServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-15T08:00:00Z");

    @Mock
    private AuthService authService;
    @Mock
    private AccountDeletionTransaction deletionTransaction;
    @Mock
    private AccountDeletionCoordinator deletionCoordinator;
    @Mock
    private AccountLifecycleDownstreamClient downstream;
    @Mock
    private JsonNode profile;
    @Mock
    private JsonNode applications;
    @Mock
    private JsonNode documents;
    @Mock
    private JsonNode payments;

    private AccountLifecycleService service;

    @BeforeEach
    void setUp() {
        service = new AccountLifecycleService(
                authService,
                deletionTransaction,
                deletionCoordinator,
                downstream,
                Clock.fixed(NOW, ZoneOffset.UTC),
                Duration.ofMinutes(15));
    }

    @Test
    void exportsTheMatchingOwnersPaymentRecordInTheVersionedArchive() {
        var account = new UserAccountResponse("owner-123", "Owner", "owner@example.test");
        var acceptance = new RegistrationLegalAcceptanceResponse(
                "2026-08-15", true, true, true, NOW.minusSeconds(60));
        when(authService.validateRecentlyAuthenticated("access-token", Duration.ofMinutes(15)))
                .thenReturn("owner-123");
        when(authService.getUserAccount("owner-123")).thenReturn(account);
        when(authService.getRegistrationLegalAcceptance("owner-123"))
                .thenReturn(acceptance);
        when(downstream.exportProfile("access-token")).thenReturn(profile);
        when(downstream.exportApplications("access-token")).thenReturn(applications);
        when(downstream.exportDocuments("access-token")).thenReturn(documents);
        when(downstream.exportPayments("owner-123")).thenReturn(payments);

        var result = service.export("access-token");

        assertEquals("job-seeker-copilot-personal-data.v3", result.schemaVersion());
        assertEquals(NOW, result.generatedAt());
        assertSame(payments, result.payments());
        verify(downstream).exportPayments("owner-123");
    }
}
