package com.jobseekercopilot.authenticationservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class ServiceIdentityFilter extends OncePerRequestFilter {

    public static final String SERVICE_HEADER = "X-Service-Token";
    public static final String ENVIRONMENT_DATA_HEADER = "X-Environment-Data-Token";
    static final String SERVICE_AUTHORITY = "SERVICE";
    static final String ENVIRONMENT_DATA_AUTHORITY = "ENVIRONMENT_DATA";

    private final ServiceIdentityCredentials credentials;

    public ServiceIdentityFilter(ServiceIdentityCredentials credentials) {
        this.credentials = credentials;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        if (requiresServiceIdentity(path)) {
            authenticate(request, SERVICE_HEADER, SERVICE_AUTHORITY, credentials::matchesServiceToken);
        } else if (path.startsWith("/internal/system-data/")) {
            authenticate(request, ENVIRONMENT_DATA_HEADER, ENVIRONMENT_DATA_AUTHORITY,
                    credentials::matchesEnvironmentDataToken);
        }
        filterChain.doFilter(request, response);
    }

    private static boolean requiresServiceIdentity(String path) {
        return path.startsWith("/api/auth/")
                || path.startsWith("/v3/api-docs")
                || path.startsWith("/swagger-ui");
    }

    private void authenticate(
            HttpServletRequest request, String header, String authority, TokenMatcher matcher) {
        List<String> values = Collections.list(request.getHeaders(header));
        if (values.size() == 1 && matcher.matches(values.get(0))) {
            var authentication = UsernamePasswordAuthenticationToken.authenticated(
                    authority.toLowerCase(), null, List.of(new SimpleGrantedAuthority(authority)));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }

    @FunctionalInterface
    private interface TokenMatcher {
        boolean matches(String candidate);
    }
}
