package com.jobseekercopilot.authenticationservice.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.tags.Tag;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Jobseeker Copilot - Authentication Service API")
                        .description("Authentication and user management microservice providing JWT-based stateless authentication, user registration, and token validation.")
                        .version("1.0.0"))
                .tags(List.of(
                        new Tag().name("Authentication").description("User registration, login, and token management"),
                        new Tag().name("Users").description("User lookup and management operations")
                ));
    }
}