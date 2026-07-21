package com.jobseekercopilot.authenticationservice;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:auth12local;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
})
@ActiveProfiles("local")
@ExtendWith(OutputCaptureExtension.class)
class LocalSecurityConfigurationContextTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    void localProfileHasNoFallbackIdentityOrCredentialLog(CapturedOutput output) {
        assertTrue(applicationContext.getBeansOfType(UserDetailsService.class).isEmpty());
        assertFalse(output.getAll().contains("generated security " + "password"));
        assertFalse(output.getAll().contains("inMemoryUserDetailsManager"));
    }
}
