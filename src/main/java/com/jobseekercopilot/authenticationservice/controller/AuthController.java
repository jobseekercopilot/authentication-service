package com.jobseekercopilot.authenticationservice.controller;

import com.jobseekercopilot.authenticationservice.exception.TokenValidationException;
import com.jobseekercopilot.authenticationservice.model.*;
import com.jobseekercopilot.authenticationservice.service.AuthService;
import com.jobseekercopilot.authenticationservice.service.AccountLifecycleService;
import com.jobseekercopilot.authenticationservice.service.PasswordResetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;
    private final AccountLifecycleService accountLifecycleService;

    public AuthController(
            AuthService authService,
            PasswordResetService passwordResetService,
            AccountLifecycleService accountLifecycleService) {
        this.authService = authService;
        this.passwordResetService = passwordResetService;
        this.accountLifecycleService = accountLifecycleService;
    }

    @GetMapping("/me")
    @Operation(
            operationId = "getCurrentUser",
            summary = "Get current authenticated user",
            description = "Returns the current user account. Both a trusted service identity and the user's bearer JWT are required.")
    @Tag(name = "Authentication")
    public ResponseEntity<UserAccountResponse> getCurrentUser(
            @RequestHeader(name = "Authorization", required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ") || authHeader.length() == 7) {
            throw TokenValidationException.required();
        }

        String token = authHeader.substring(7);
        String userId = authService.validate(token);

        UserAccountResponse account = authService.getUserAccount(userId);

        return ResponseEntity.ok(account);
    }

    @PostMapping("/register")
    @Operation(summary = "Register a new user", description = "Registers a new user account with the provided details. Returns a success message on completion.")
    @Tag(name = "Authentication")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegisterRequest request) {
        authService.register(request);
        Map<String, String> response = new HashMap<>();
        response.put("message", "User registered successfully.");
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping(value = "/registration-requirements", produces = "application/json")
    @Operation(
            operationId = "getRegistrationLegalRequirements",
            summary = "Get the current registration legal requirements",
            description = "Returns the server-authoritative legal version, minimum age and reviewed HTTPS document URLs required for registration.")
    @Tag(name = "Authentication")
    public ResponseEntity<RegistrationLegalRequirements> registrationRequirements() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noCache())
                .body(authService.getRegistrationLegalRequirements());
    }

    @PostMapping("/login")
    @Operation(summary = "Authenticate user and get JWT token", description = "Authenticates a user with username and password credentials. Returns a JWT token and user details upon successful authentication.")
    @Tag(name = "Authentication")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Rotate a refresh token", description = "Consumes a one-time refresh token and returns a new access/refresh token pair.")
    @Tag(name = "Authentication")
    public ResponseEntity<LoginResponse> refresh(@RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refresh(request == null ? null : request.refreshToken()));
    }

    @PostMapping("/logout")
    @Operation(summary = "Revoke the current session", description = "Immediately revokes the session identified by the bearer access token.")
    @Tag(name = "Authentication")
    public ResponseEntity<Void> logout(
            @RequestHeader(name = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ") || authHeader.length() == 7) {
            throw TokenValidationException.required();
        }
        authService.logout(authHeader.substring(7));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/password-reset/request")
    @Operation(
            operationId = "requestPasswordReset",
            summary = "Request a password-reset email",
            description = "Returns the same accepted response whether or not an active account exists.")
    @Tag(name = "Authentication")
    public ResponseEntity<Map<String, String>> requestPasswordReset(
            @RequestBody PasswordResetRequest request) {
        passwordResetService.requestReset(request);
        return ResponseEntity.accepted().body(Map.of(
                "message", "If an account exists for that email, a password-reset link has been sent."));
    }

    @PostMapping("/password-reset/complete")
    @Operation(
            operationId = "completePasswordReset",
            summary = "Complete a password reset",
            description = "Atomically consumes a password-reset token, changes the password, and revokes all sessions.")
    @Tag(name = "Authentication")
    public ResponseEntity<Map<String, String>> completePasswordReset(
            @RequestBody PasswordResetCompletionRequest request) {
        passwordResetService.completeReset(request);
        return ResponseEntity.ok(Map.of(
                "message", "Your password has been changed. Sign in with your new password."));
    }

    @GetMapping(value = "/account/export", produces = "application/json")
    @Operation(
            operationId = "exportPersonalData",
            summary = "Export personal account data",
            description = "Requires a session created by sign-in within the last 15 minutes. The synchronous JSON response is not retained by the service.")
    @ApiResponse(responseCode = "200", description = "Complete no-store personal-data export")
    @Tag(name = "Account lifecycle")
    public ResponseEntity<PersonalDataExport> exportPersonalData(
            @RequestHeader(name = "Authorization") String authHeader) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"job-seeker-copilot-personal-data.json\"")
                .body(accountLifecycleService.export(bearer(authHeader)));
    }

    @DeleteMapping("/account")
    @Operation(
            operationId = "deleteAccount",
            summary = "Delete the current account and owned data",
            description = "Disables credentials first and starts an idempotent, retryable cross-service deletion operation. Document content follows DOC-09 recoverable deletion and legal-hold rules.")
    @ApiResponse(responseCode = "202", description = "Deletion accepted or safely resumed")
    @Tag(name = "Account lifecycle")
    public ResponseEntity<AccountDeletionResponse> deleteAccount(
            @RequestHeader(name = "Authorization") String authHeader,
            @Parameter(
                    required = true,
                    schema = @Schema(
                            minLength = 16,
                            maxLength = 128,
                            pattern = "[A-Za-z0-9][A-Za-z0-9._:-]{15,127}"))
            @RequestHeader(name = "Idempotency-Key")
            String idempotencyKey) {
        return ResponseEntity.accepted()
                .cacheControl(CacheControl.noStore())
                .body(accountLifecycleService.delete(
                        bearer(authHeader), idempotencyKey));
    }

    private String bearer(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")
                || authHeader.length() == 7) {
            throw TokenValidationException.required();
        }
        return authHeader.substring(7);
    }
}
