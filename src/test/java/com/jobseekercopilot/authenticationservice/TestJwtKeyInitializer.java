package com.jobseekercopilot.authenticationservice;

import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

public class TestJwtKeyInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    @Override
    public void initialize(ConfigurableApplicationContext context) {
        TestPropertyValues.of(
                "jwt.private-key-base64=" + TestJwtKeys.privateKey(TestJwtKeys.ACTIVE),
                "jwt.public-key-base64=" + TestJwtKeys.publicKey(TestJwtKeys.ACTIVE),
                "jwt.key-id=" + TestJwtKeys.ACTIVE_KEY_ID)
                .applyTo(context.getEnvironment());
    }
}
