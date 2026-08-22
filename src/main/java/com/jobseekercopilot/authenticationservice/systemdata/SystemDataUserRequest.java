package com.jobseekercopilot.authenticationservice.systemdata;

import java.time.LocalDateTime;

public record SystemDataUserRequest(
        String scenarioId,
        String userId,
        String name,
        String email,
        String password,
        LocalDateTime createdAt) {
}
