package com.jobseekercopilot.authenticationservice.config;

import org.junit.jupiter.api.Test;
import org.postgresql.Driver;

import static org.assertj.core.api.Assertions.assertThat;

class PostgresqlDriverVersionTest {

    @Test
    void resolvesReviewedDriverVersionWithScramDowngradeFix() {
        assertThat(Driver.class.getPackage().getImplementationVersion())
                .as("PostgreSQL JDBC runtime version")
                .isEqualTo("42.7.12");
    }
}
