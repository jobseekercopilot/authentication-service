package com.jobseekercopilot.authenticationservice.systemdata;

import com.jobseekercopilot.authenticationservice.email.FixtureAccountEmail;
import com.jobseekercopilot.authenticationservice.email.FixtureAccountEmailSender;
import io.swagger.v3.oas.annotations.Hidden;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/system-data/account-email")
@Hidden
@ConditionalOnProperty(
        name = "auth.account-email.delivery-mode",
        havingValue = "fixture",
        matchIfMissing = true)
public class FixtureAccountEmailController {

    private final EnvironmentDataGuard guard;
    private final FixtureAccountEmailSender sender;

    public FixtureAccountEmailController(
            EnvironmentDataGuard guard, FixtureAccountEmailSender sender) {
        this.guard = guard;
        this.sender = sender;
    }

    @GetMapping("/latest")
    public ResponseEntity<Map<String, Object>> latest(
            @RequestParam String recipient, @RequestParam String purpose) {
        guard.requireEnabled();
        return sender.latest(recipient, purpose)
                .map(this::response)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping
    public ResponseEntity<Void> clear() {
        guard.requireEnabled();
        sender.clear();
        return ResponseEntity.noContent().build();
    }

    private Map<String, Object> response(FixtureAccountEmail email) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("purpose", email.purpose());
        body.put("recipient", email.recipient());
        body.put("actionUrl", email.actionUrl() == null ? "" : email.actionUrl().toASCIIString());
        body.put("expiresAt", email.expiresAt() == null ? "" : email.expiresAt().toString());
        body.put("sentAt", email.sentAt().toString());
        return body;
    }
}
