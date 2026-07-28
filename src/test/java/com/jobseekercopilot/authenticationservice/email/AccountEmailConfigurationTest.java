package com.jobseekercopilot.authenticationservice.email;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import software.amazon.awssdk.services.ses.SesClient;

class AccountEmailConfigurationTest {

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner()
                    .withUserConfiguration(AccountEmailConfiguration.class);

    @Test
    void fixtureModeDoesNotConstructAnSesClient() {
        contextRunner
                .withPropertyValues("auth.account-email.delivery-mode=fixture")
                .run(context -> assertThat(context)
                        .doesNotHaveBean(SesClient.class));
    }

    @Test
    void localSesUsesOnlyTheBoundedLocalStackEndpointAndDummyCredentials() {
        contextRunner
                .withPropertyValues(
                        "auth.account-email.delivery-mode=local-ses",
                        "auth.account-email.ses.region=eu-west-2",
                        "auth.account-email.ses.endpoint=http://localstack:4566",
                        "AWS_ACCESS_KEY_ID=test",
                        "AWS_SECRET_ACCESS_KEY=test")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(SesClient.class);
                });
    }

    @Test
    void localSesRejectsAnyOtherEndpoint() {
        contextRunner
                .withPropertyValues(
                        "auth.account-email.delivery-mode=local-ses",
                        "auth.account-email.ses.region=eu-west-2",
                        "auth.account-email.ses.endpoint=https://email.eu-west-2.amazonaws.com",
                        "AWS_ACCESS_KEY_ID=test",
                        "AWS_SECRET_ACCESS_KEY=test")
                .run(context -> assertThat(context.getStartupFailure())
                        .hasRootCauseMessage(
                                "local-ses endpoint must be the Compose-local LocalStack gateway"));
    }

    @Test
    void localSesRejectsNonDummyCredentials() {
        contextRunner
                .withPropertyValues(
                        "auth.account-email.delivery-mode=local-ses",
                        "auth.account-email.ses.region=eu-west-2",
                        "auth.account-email.ses.endpoint=http://localstack:4566",
                        "AWS_ACCESS_KEY_ID=not-local",
                        "AWS_SECRET_ACCESS_KEY=not-local")
                .run(context -> assertThat(context.getStartupFailure())
                        .hasRootCauseMessage(
                                "local-ses requires the exact dummy LocalStack credentials"));
    }

    @Test
    void hostedSesRejectsEndpointOverrides() {
        contextRunner
                .withPropertyValues(
                        "auth.account-email.delivery-mode=ses",
                        "auth.account-email.ses.region=eu-west-2",
                        "auth.account-email.ses.endpoint=http://localstack:4566")
                .run(context -> assertThat(context.getStartupFailure())
                        .hasRootCauseMessage(
                                "SES endpoint override is forbidden in hosted ses mode"));
    }

    @Test
    void hostedSesRejectsDummyLocalStackCredentials() {
        contextRunner
                .withPropertyValues(
                        "auth.account-email.delivery-mode=ses",
                        "auth.account-email.ses.region=eu-west-2",
                        "AWS_ACCESS_KEY_ID=test",
                        "AWS_SECRET_ACCESS_KEY=test")
                .run(context -> assertThat(context.getStartupFailure())
                        .hasRootCauseMessage(
                                "Dummy LocalStack credentials are forbidden in hosted ses mode"));
    }
}
