package com.jobseekercopilot.authenticationservice.email;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.net.URI;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.SendEmailRequest;

class SesAccountEmailSenderTest {

    @Test
    void resetEmailUsesTheDedicatedSenderConfigurationSetAndPurposeTag() {
        SesV2Client client = mock(SesV2Client.class);
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
        assertEquals("accounts@jobseekercopilot.com", sent.fromEmailAddress());
        assertEquals("JobSeekerCopilotAccountEmails", sent.configurationSetName());
        assertEquals(java.util.List.of("person@example.test"), sent.destination().toAddresses());
        assertEquals("message-purpose", sent.emailTags().get(0).name());
        assertEquals("password-reset", sent.emailTags().get(0).value());
        assertTrue(sent.content().simple().body().text().data().contains(link.toASCIIString()));
        assertTrue(sent.content().simple().body().html().data().contains(link.toASCIIString()));
    }

    @Test
    void changedNotificationUsesItsOwnPurposeAndContainsNoResetLink() {
        SesV2Client client = mock(SesV2Client.class);
        SesAccountEmailSender sender = new SesAccountEmailSender(
                client, "accounts@jobseekercopilot.com",
                "JobSeekerCopilotAccountEmails", "https://jobseekercopilot.com/contact");

        sender.sendPasswordChanged("account-123", "person@example.test");

        ArgumentCaptor<SendEmailRequest> request = ArgumentCaptor.forClass(SendEmailRequest.class);
        verify(client).sendEmail(request.capture());
        assertEquals("password-changed", request.getValue().emailTags().get(0).value());
        assertTrue(request.getValue().content().simple().body().text().data()
                .contains("Every existing session has been signed out."));
    }
}
