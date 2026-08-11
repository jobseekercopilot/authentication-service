package com.jobseekercopilot.authenticationservice.systemdata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.jobseekercopilot.authenticationservice.identity.EmailIdentityCanonicalizer;
import com.jobseekercopilot.authenticationservice.model.User;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

class AuthenticationSystemDataControllerTest {
    private EnvironmentDataGuard guard;
    private UserRepository repository;
    private AuthenticationSystemDataController controller;

    @BeforeEach
    void setUp() {
        guard = mock(EnvironmentDataGuard.class);
        repository = mock(UserRepository.class);
        when(guard.activeEnvironment()).thenReturn("e2e");
        controller = new AuthenticationSystemDataController(
                guard,
                repository,
                mock(PasswordEncoder.class),
                new EmailIdentityCanonicalizer());
    }

    @Test
    void resolvesTheRuntimeIdOfAReservedSyntheticRegistrationAccount() {
        User user = new User(
                "c1dfc1da-590e-47b3-9634-db65a2786f42",
                "Registration Tester",
                "registration.primary@example.com",
                "registration.primary@example.com",
                "hash",
                LocalDateTime.now(),
                true);
        when(repository.findByCanonicalEmail("registration.primary@example.com"))
                .thenReturn(Optional.of(user));

        SystemDataResult result = controller
                .resolveSyntheticUser(" Registration.Primary@EXAMPLE.com ")
                .getBody();

        assertThat(result).isNotNull();
        assertThat(result.recordsAffected()).isEqualTo(1);
        assertThat(result.details())
                .containsEntry("exists", true)
                .containsEntry("userId", user.getId());
        verify(guard).requireEnabled();
    }

    @Test
    void rejectsResolutionOutsideTheReservedSyntheticDomain() {
        assertThatThrownBy(() -> controller.resolveSyntheticUser("customer@example.org"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reserved example.com");
        verify(guard).requireEnabled();
    }
}
