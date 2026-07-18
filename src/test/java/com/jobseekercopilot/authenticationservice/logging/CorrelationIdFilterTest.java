package com.jobseekercopilot.authenticationservice.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import jakarta.servlet.ServletException;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class CorrelationIdFilterTest {

    private final CorrelationIdFilter filter = new CorrelationIdFilter("authentication-service");

    @Test
    void generatesCorrelationIdWhenMissingAndClearsMdc() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/auth/me");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertNotNull(response.getHeader(CorrelationIdFilter.HEADER_NAME));
        assertNull(MDC.get(CorrelationIdFilter.MDC_KEY));
        assertNull(MDC.get(CorrelationIdFilter.SERVICE_MDC_KEY));
    }

    @Test
    void preservesExistingCorrelationId() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        request.addHeader(CorrelationIdFilter.HEADER_NAME, "existing-correlation-id");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals("existing-correlation-id", response.getHeader(CorrelationIdFilter.HEADER_NAME));
        assertNull(MDC.get(CorrelationIdFilter.MDC_KEY));
        assertNull(MDC.get(CorrelationIdFilter.SERVICE_MDC_KEY));
    }
}
