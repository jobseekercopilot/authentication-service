package com.jobseekercopilot.authenticationservice.email;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.net.URI;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.services.ses.SesClient;
import software.amazon.awssdk.services.ses.model.SendEmailRequest;

class SesAccountEmailSenderTest {

    @Test
    void resetEmailUsesTheDedicatedSenderConfigurationSetAndPurposeTag() {
        SesClient client = mock(SesClient.class);
        SesAccountEmailSender sender = new SesAccountEmailSender(
                client,
                "accounts@jobseekercopilot.com",
                "JobSeekerCopilotAccountEmails",
                "https://jobseekercopilot.com/contact");
        URI link = URI.create(
                "https://app.jobseekercopilot.com/reset-password#token=" + "A".repeat(43));

        sender.sendPasswordReset(
                "account-123", "person@example.test", link,
                Instant.parse("2026-07-28T12:30:00Z"));

        ArgumentCaptor<SendEmailRequest> request = ArgumentCaptor.forClass(SendEmailRequest.class);
        verify(client).sendEmail(request.capture());
        SendEmailRequest sent = request.getValue();
        assertEquals("accounts@jobseekercopilot.com", sent.source());
        assertEquals("JobSeekerCopilotAccountEmails", sent.configurationSetName());
        assertEquals(java.util.List.of("person@example.test"), sent.destination().toAddresses());
        assertEquals("message-purpose", sent.tags().get(0).name());
        assertEquals("password-reset", sent.tags().get(0).value());
        assertTrue(sent.message().body().text().data().contains(link.toASCIIString()));
        assertTrue(sent.message().body().html().data().contains(link.toASCIIString()));
    }

    @Test
    void changedNotificationUsesItsOwnPurposeAndContainsNoResetLink() {
        SesClient client = mock(SesClient.class);
        SesAccountEmailSender sender = new SesAccountEmailSender(
                client, "accounts@jobseekercopilot.com",
                "JobSeekerCopilotAccountEmails", "https://jobseekercopilot.com/contact");

        sender.sendPasswordChanged("account-123", "person@example.test");

        ArgumentCaptor<SendEmailRequest> request = ArgumentCaptor.forClass(SendEmailRequest.class);
        verify(client).sendEmail(request.capture());
        assertEquals("password-changed", request.getValue().tags().get(0).value());
        assertTrue(request.getValue().message().body().text().data()
                .contains("Every existing session has been signed out."));
    }
}
