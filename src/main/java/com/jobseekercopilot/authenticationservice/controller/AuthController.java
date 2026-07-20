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
    @Operation(summary = "Get current authenticated user", description = "Returns the user account details for the currently authenticated user based on the JWT token provided in the Authorization header.")
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
}
