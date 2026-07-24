package com.jobseekercopilot.authenticationservice.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.tags.Tag;
import java.util.List;
import org.springdoc.core.customizers.OpenApiCustomizer;
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
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT"))
                        .addSecuritySchemes("serviceToken", new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name("X-Service-Token")))
                .tags(List.of(
                        new Tag().name("Authentication").description("User registration, login, and token management"),
                        new Tag().name("Users").description("User lookup and management operations")
                ));
    }

    @Bean
    public OpenApiCustomizer currentUserSecurityCustomizer() {
        return openApi -> {
            var operation = openApi.getPaths().get("/api/auth/me").getGet();
            operation.setSecurity(List.of(new SecurityRequirement()
                    .addList("bearerAuth")
                    .addList("serviceToken")));
        };
    }
}
