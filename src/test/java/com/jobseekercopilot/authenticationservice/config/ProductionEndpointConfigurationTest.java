package com.jobseekercopilot.authenticationservice.config;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class ProductionEndpointConfigurationTest {

    @Test
    void productionDisablesDevelopmentEndpointsAndDetailedHealth() throws IOException {
        Properties properties = new Properties();
        try (InputStream input = getClass().getResourceAsStream("/application-production.properties")) {
            properties.load(input);
        }

        assertEquals("false", properties.getProperty("spring.h2.console.enabled"));
        assertEquals("false", properties.getProperty("springdoc.api-docs.enabled"));
        assertEquals("false", properties.getProperty("springdoc.swagger-ui.enabled"));
        assertEquals("never", properties.getProperty("management.endpoint.health.show-details"));
    }
}
