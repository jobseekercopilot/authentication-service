package com.jobseekercopilot.authenticationservice.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    FilterRegistrationBean<ServiceIdentityFilter> disableContainerRegistration(
            ServiceIdentityFilter identityFilter) {
        FilterRegistrationBean<ServiceIdentityFilter> registration = new FilterRegistrationBean<>(identityFilter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, ServiceIdentityFilter identityFilter)
            throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((request, response, exception) -> writeError(
                                response, HttpServletResponse.SC_UNAUTHORIZED,
                                "SERVICE_AUTHENTICATION_REQUIRED",
                                "Valid service authentication is required."))
                        .accessDeniedHandler((request, response, exception) -> writeError(
                                response, HttpServletResponse.SC_FORBIDDEN,
                                "ACCESS_DENIED", "Access is denied.")))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers("/.well-known/jwks.json").permitAll()
                        .requestMatchers("/internal/system-data/**")
                        .hasAuthority(ServiceIdentityFilter.ENVIRONMENT_DATA_AUTHORITY)
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html")
                        .hasAuthority(ServiceIdentityFilter.SERVICE_AUTHORITY)
                        .requestMatchers("/api/auth/**")
                        .hasAuthority(ServiceIdentityFilter.SERVICE_AUTHORITY)
                        .anyRequest().denyAll())
                .addFilterBefore(identityFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    private static void writeError(HttpServletResponse response, int status, String code, String message)
            throws java.io.IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}");
    }
}
