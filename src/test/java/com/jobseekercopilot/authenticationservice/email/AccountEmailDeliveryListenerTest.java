package com.jobseekercopilot.authenticationservice.email;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.jobseekercopilot.authenticationservice.service.PasswordChanged;
import com.jobseekercopilot.authenticationservice.service.PasswordResetEmailRequested;
import java.net.URI;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.ses.model.SesException;

@ExtendWith(OutputCaptureExtension.class)
class AccountEmailDeliveryListenerTest {

    private static final String RAW_TOKEN = "A".repeat(43);

    @Test
    void buildsAFragmentLinkAndNeverLogsResetMaterial(CapturedOutput output) {
        AccountEmailSender sender = mock(AccountEmailSender.class);
        AccountEmailDeliveryListener listener = new AccountEmailDeliveryListener(
                sender, "https://app.jobseekercopilot.com", "ses");

        listener.onPasswordResetRequested(new PasswordResetEmailRequested(
                "account-123", "person@example.test", RAW_TOKEN,
                Instant.parse("2026-07-28T12:00:00Z")));

        ArgumentCaptor<URI> link = ArgumentCaptor.forClass(URI.class);
        verify(sender).sendPasswordReset(
                eq("account-123"), eq("person@example.test"), link.capture(), any());
        org.junit.jupiter.api.Assertions.assertEquals(
                "https://app.jobseekercopilot.com/reset-password#token=" + RAW_TOKEN,
                link.getValue().toASCIIString());
        assertFalse(output.getAll().contains(RAW_TOKEN));
        assertFalse(output.getAll().contains("person@example.test"));
    }

    @Test
    void containsDeliveryFailureWithoutLeakingTokenOrRecipient(CapturedOutput output) {
        AccountEmailSender sender = mock(AccountEmailSender.class);
        doThrow(new IllegalStateException("provider detail containing " + RAW_TOKEN))
                .when(sender).sendPasswordReset(any(), any(), any(), any());
        AccountEmailDeliveryListener listener = new AccountEmailDeliveryListener(
                sender, "https://app.jobseekercopilot.com", "ses");

        assertDoesNotThrow(() -> listener.onPasswordResetRequested(
                new PasswordResetEmailRequested(
                        "account-123", "person@example.test", RAW_TOKEN,
                        Instant.parse("2026-07-28T12:00:00Z"))));

        assertFalse(output.getAll().contains(RAW_TOKEN));
        assertFalse(output.getAll().contains("person@example.test"));
    }

    @Test
    void logsOnlySanitizedAwsFailureMetadata(CapturedOutput output) {
        AccountEmailSender sender = mock(AccountEmailSender.class);
        AwsServiceException failure = SesException.builder()
                .message("provider detail containing person@example.test and " + RAW_TOKEN)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("AccessDeniedException")
                        .errorMessage("sensitive provider detail containing " + RAW_TOKEN)
                        .build())
                .statusCode(403)
                .requestId("request-id-123")
                .build();
        doThrow(failure).when(sender).sendPasswordReset(any(), any(), any(), any());
        AccountEmailDeliveryListener listener = new AccountEmailDeliveryListener(
                sender, "https://app.jobseekercopilot.com", "ses");

        assertDoesNotThrow(() -> listener.onPasswordResetRequested(
                new PasswordResetEmailRequested(
                        "account-123", "person@example.test", RAW_TOKEN,
                        Instant.parse("2026-07-28T12:00:00Z"))));

        String logs = output.getAll();
        assertTrue(logs.contains("awsErrorCode=AccessDeniedException"));
        assertTrue(logs.contains("httpStatus=403"));
        assertTrue(logs.contains("requestId=request-id-123"));
        assertFalse(logs.contains(RAW_TOKEN));
        assertFalse(logs.contains("person@example.test"));
        assertFalse(logs.contains("sensitive provider detail"));
    }

    @Test
    void rejectsRemoteHttpButAllowsBoundedFixtureAndLocalSesLinks() {
        AccountEmailSender sender = mock(AccountEmailSender.class);
        assertThrows(IllegalStateException.class, () ->
                new AccountEmailDeliveryListener(sender, "http://example.test", "ses"));
        assertThrows(IllegalStateException.class, () ->
                new AccountEmailDeliveryListener(sender, "http://example.test", "local-ses"));
        assertDoesNotThrow(() ->
                new AccountEmailDeliveryListener(sender, "http://localhost:3100", "fixture"));
        assertDoesNotThrow(() ->
                new AccountEmailDeliveryListener(sender, "http://localhost:3100", "local-ses"));
        assertThrows(IllegalStateException.class, () ->
                new AccountEmailDeliveryListener(sender, "http://localhost:3100/path", "local-ses"));
        AccountEmailDeliveryListener listener = new AccountEmailDeliveryListener(
                sender, "https://app.jobseekercopilot.com", "ses");
        assertDoesNotThrow(() -> listener.onPasswordChanged(
                new PasswordChanged("account-123", "person@example.test")));
    }
}
