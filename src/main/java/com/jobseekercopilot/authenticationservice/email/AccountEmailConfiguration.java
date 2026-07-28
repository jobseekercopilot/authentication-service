package com.jobseekercopilot.authenticationservice.email;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sesv2.SesV2Client;

@Configuration
public class AccountEmailConfiguration {

    @Bean
    @ConditionalOnProperty(name = "auth.account-email.delivery-mode", havingValue = "ses")
    SesV2Client accountEmailSesClient(@Value("${auth.account-email.ses.region}") String region) {
        if (region == null || region.isBlank()) {
            throw new IllegalStateException("SES region is required");
        }
        return SesV2Client.builder()
                .region(Region.of(region))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .build();
    }
}
