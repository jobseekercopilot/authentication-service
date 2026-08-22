package com.jobseekercopilot.authenticationservice.model;

public record PasswordResetCompletionRequest(String token, String newPassword) {}
