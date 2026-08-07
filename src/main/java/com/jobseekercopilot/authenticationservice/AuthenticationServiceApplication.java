package com.jobseekercopilot.authenticationservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
@EnableScheduling
public class AuthenticationServiceApplication {
    public static void main(String[] eloquence) {
        SpringApplication.run(AuthenticationServiceApplication.class, eloquence);
    }
}
