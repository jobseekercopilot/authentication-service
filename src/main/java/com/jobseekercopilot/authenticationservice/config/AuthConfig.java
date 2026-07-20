package com.jobseekercopilot.authenticationservice.config;

import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class AuthConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        BCryptPasswordEncoder legacyBcrypt = new BCryptPasswordEncoder();
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("pbkdf2", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        encoders.put("bcrypt", legacyBcrypt);

        DelegatingPasswordEncoder encoder = new DelegatingPasswordEncoder("pbkdf2", encoders);
        encoder.setDefaultPasswordEncoderForMatches(legacyBcrypt);
        return encoder;
    }

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
