package com.jobseekercopilot.authenticationservice.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("production")
public class ProductionDatabaseSafetyConfiguration {
    private final String url;
    private final String username;
    private final String password;

    public ProductionDatabaseSafetyConfiguration(
            @Value("${spring.datasource.url}") String url,
            @Value("${spring.datasource.username}") String username,
            @Value("${spring.datasource.password}") String password) {
        this.url = url;
        this.username = username;
        this.password = password;
    }

    @PostConstruct
    void validate() {
        if (url == null || !url.startsWith("jdbc:postgresql://")) {
            throw new IllegalStateException("Production authentication database must use PostgreSQL.");
        }
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new IllegalStateException("Production authentication database credentials are required.");
        }
    }
}
