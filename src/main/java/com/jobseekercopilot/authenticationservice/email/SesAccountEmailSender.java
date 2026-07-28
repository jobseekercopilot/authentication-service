package com.jobseekercopilot.authenticationservice.email;

import java.net.URI;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.Body;
import software.amazon.awssdk.services.sesv2.model.Content;
import software.amazon.awssdk.services.sesv2.model.Destination;
import software.amazon.awssdk.services.sesv2.model.EmailContent;
import software.amazon.awssdk.services.sesv2.model.MessageTag;
import software.amazon.awssdk.services.sesv2.model.Message;
import software.amazon.awssdk.services.sesv2.model.SendEmailRequest;

@Component
@ConditionalOnProperty(name = "auth.account-email.delivery-mode", havingValue = "ses")
public class SesAccountEmailSender implements AccountEmailSender {

    private static final DateTimeFormatter EXPIRY_FORMAT =
            DateTimeFormatter.ofPattern("d MMM uuuu 'at' HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private final SesV2Client ses;
    private final String sender;
    private final String configurationSet;
    private final String supportUrl;

    public SesAccountEmailSender(
            SesV2Client ses,
            @Value("${auth.account-email.sender}") String sender,
            @Value("${auth.account-email.ses.configuration-set}") String configurationSet,
            @Value("${auth.account-email.support-url}") String supportUrl) {
        this.ses = ses;
        this.sender = requireText(sender, "Account-email sender");
        this.configurationSet = requireText(configurationSet, "SES configuration set");
        this.supportUrl = requireHttps(supportUrl, "Account-email support URL");
    }

    @Override
    public void sendPasswordReset(
            String accountId, String recipient, URI resetLink, Instant expiresAt) {
        String resetUrl = resetLink.toASCIIString();
        String expiry = EXPIRY_FORMAT.format(expiresAt);
        send(
                recipient,
                "Reset your Job Seeker Copilot password",
                """
                We received a request to reset your Job Seeker Copilot password.

                Reset your password: %s

                This link expires on %s and can be used only once.
                If you did not request this, you can ignore this email. Your password has not changed.
                Need help? %s
                """.formatted(resetUrl, expiry, supportUrl),
                """
                <p>We received a request to reset your Job Seeker Copilot password.</p>
                <p><a href="%s">Reset your password</a></p>
                <p>This link expires on %s and can be used only once.</p>
                <p>If you did not request this, you can ignore this email. Your password has not changed.</p>
                <p><a href="%s">Contact support</a></p>
                """.formatted(resetUrl, expiry, supportUrl),
                "password-reset");
    }

    @Override
    public void sendPasswordChanged(String accountId, String recipient) {
        send(
                recipient,
                "Your Job Seeker Copilot password was changed",
                """
                Your Job Seeker Copilot password was changed.

                Every existing session has been signed out. If you did not make this change, contact support:
                %s
                """.formatted(supportUrl),
                """
                <p>Your Job Seeker Copilot password was changed.</p>
                <p>Every existing session has been signed out.</p>
                <p>If you did not make this change, <a href="%s">contact support</a>.</p>
                """.formatted(supportUrl),
                "password-changed");
    }

    private void send(String recipient, String subject, String text, String html, String purpose) {
        Message message = Message.builder()
                .subject(content(subject))
                .body(Body.builder().text(content(text)).html(content(html)).build())
                .build();
        ses.sendEmail(SendEmailRequest.builder()
                .fromEmailAddress(sender)
                .destination(Destination.builder().toAddresses(recipient).build())
                .content(EmailContent.builder().simple(message).build())
                .configurationSetName(configurationSet)
                .emailTags(List.of(MessageTag.builder()
                        .name("message-purpose")
                        .value(purpose)
                        .build()))
                .build());
    }

    private static Content content(String value) {
        return Content.builder().data(value).charset("UTF-8").build();
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(label + " is required");
        }
        return value;
    }

    private static String requireHttps(String value, String label) {
        String checked = requireText(value, label);
        if (!checked.startsWith("https://")) {
            throw new IllegalStateException(label + " must use HTTPS");
        }
        return checked;
    }
}
