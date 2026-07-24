package com.jobseekercopilot.authenticationservice.controller;

import com.jobseekercopilot.authenticationservice.exception.TokenValidationException;
import com.jobseekercopilot.authenticationservice.model.*;
import com.jobseekercopilot.authenticationservice.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
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
}
