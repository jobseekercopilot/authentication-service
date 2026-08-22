package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.ConflictException;
import com.jobseekercopilot.authenticationservice.exception.LoginRateLimitException;
import com.jobseekercopilot.authenticationservice.exception.ResourceNotFoundException;
import com.jobseekercopilot.authenticationservice.exception.UnauthorizedException;
import com.jobseekercopilot.authenticationservice.identity.EmailIdentityCanonicalizer;
import com.jobseekercopilot.authenticationservice.model.*;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import com.jobseekercopilot.authenticationservice.repository.RegistrationLegalAcceptanceRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.junit.jupiter.api.BeforeEach;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private PasswordPolicy passwordPolicy;

    @Mock
    private LoginAttemptService loginAttemptService;

    @Mock
    private SessionTokenService sessionTokenService;

    @Mock
    private RegistrationLegalAcceptanceRepository legalAcceptanceRepository;

    private AuthService authService;
    private final EmailIdentityCanonicalizer emailCanonicalizer = new EmailIdentityCanonicalizer();

    @BeforeEach
    void setUp() {
        when(passwordEncoder.encode("authentication-timing-placeholder")).thenReturn("dummy-hash");
        LegalAcceptancePolicy legalAcceptancePolicy = new LegalAcceptancePolicy(
                "2026-08-15",
                "https://jobseekercopilot.com/terms",
                "https://jobseekercopilot.com/privacy",
                Clock.fixed(Instant.parse("2026-08-15T00:00:00Z"), ZoneOffset.UTC));
        authService = new AuthService(userRepository, passwordEncoder, jwtTokenProvider,
                passwordPolicy, loginAttemptService, emailCanonicalizer, sessionTokenService,
                legalAcceptancePolicy, legalAcceptanceRepository);
    }

    @Test
    void register_ShouldSucceed() {
        RegisterRequest request = accepted(
                "John", "john@test.com", "A-valid-local password 2026!");
        when(userRepository.findByCanonicalEmail("john@test.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("A-valid-local password 2026!")).thenReturn("hashed-password");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        assertDoesNotThrow(() -> authService.register(request));

        verify(userRepository, times(1)).findByCanonicalEmail("john@test.com");
        verify(userRepository).save(argThat(user ->
                user.getEmail().equals("john@test.com")
                        && user.getCanonicalEmail().equals("john@test.com")));
        verify(legalAcceptanceRepository).save(argThat(acceptance ->
                acceptance.getUserId() != null
                        && acceptance.getLegalVersion().equals("2026-08-15")
                        && acceptance.isAgeEligibilityConfirmed()));
    }

    @Test
    void register_ShouldThrowConflict_WhenEmailExists() {
        RegisterRequest request = accepted(
                "John", "existing@test.com", "A-valid-local password 2026!");
        when(userRepository.findByCanonicalEmail("existing@test.com")).thenReturn(Optional.of(new User()));

        assertThrows(ConflictException.class, () -> authService.register(request));
        verify(userRepository, never()).save(any());
    }

    @Test
    void registerPreservesDisplayEmailAndRejectsCanonicalVariant() {
        RegisterRequest request = accepted(
                "John", "\u00a0Case.User@Example.Test\u2003", "A-valid-local password 2026!");
        when(userRepository.findByCanonicalEmail("case.user@example.test"))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(request.getPassword())).thenReturn("hashed-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        authService.register(request);

        verify(userRepository).save(argThat(user ->
                user.getEmail().equals("Case.User@Example.Test")
                        && user.getCanonicalEmail().equals("case.user@example.test")));
    }

    @Test
    void concurrentCanonicalConstraintConflictReturnsStableAccountConflict() {
        RegisterRequest request = accepted(
                "John", "Case.User@Example.Test", "A-valid-local password 2026!");
        when(userRepository.findByCanonicalEmail("case.user@example.test"))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(request.getPassword())).thenReturn("hashed-password");
        when(userRepository.save(any(User.class)))
                .thenThrow(new DataIntegrityViolationException("sensitive database detail"));

        ConflictException failure = assertThrows(ConflictException.class, () -> authService.register(request));

        assertEquals("An account with this email already exists.", failure.getMessage());
    }

    @Test
    void login_ShouldSucceed() {
        String userId = UUID.randomUUID().toString();
        User user = new User(
                userId, "John", "john@test.com", "john@test.com",
                "hashed-password", LocalDateTime.now(), true);
        LoginRequest request = new LoginRequest("john@test.com", "A-valid-local password 2026!");

        when(userRepository.findByCanonicalEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("A-valid-local password 2026!", "hashed-password")).thenReturn(true);
        when(sessionTokenService.issue(userId)).thenReturn(new LoginResponse("jwt-token"));

        LoginResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("jwt-token", response.getToken());
        verify(loginAttemptService).recordSuccess("john@test.com");
    }

    @Test
    void loginUsesCanonicalIdentityForLookupAndRateLimit() {
        User user = new User(
                "id", "John", "Ｊohn@Example.Test", "john@example.test",
                "hashed-password", LocalDateTime.now(), true);
        LoginRequest request = new LoginRequest("\u00a0ＪOHN@ＥXAMPLE.TEST\u2003", "valid-password");
        when(userRepository.findByCanonicalEmail("john@example.test")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("valid-password", "hashed-password")).thenReturn(true);

        authService.login(request);

        verify(loginAttemptService).retryAfterSecondsIfBlocked("john@example.test");
        verify(loginAttemptService).recordSuccess("john@example.test");
    }

    @Test
    void login_ShouldThrowUnauthorized_WhenInvalidPassword() {
        User user = new User(
                "id", "John", "john@test.com", "john@test.com",
                "hashed-password", LocalDateTime.now(), true);
        LoginRequest request = new LoginRequest("john@test.com", "wrong-password");

        when(userRepository.findByCanonicalEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", "hashed-password")).thenReturn(false);

        UnauthorizedException exception = assertThrows(UnauthorizedException.class, () -> authService.login(request));
        assertEquals("Invalid email or password.", exception.getMessage());
        verify(loginAttemptService).recordFailure("john@test.com");
    }

    @Test
    void login_ShouldUseSameFailureForUnknownUser() {
        LoginRequest request = new LoginRequest("missing@test.com", "wrong-password");
        when(userRepository.findByCanonicalEmail("missing@test.com")).thenReturn(Optional.empty());
        when(passwordEncoder.matches("wrong-password", "dummy-hash")).thenReturn(false);

        UnauthorizedException exception = assertThrows(UnauthorizedException.class, () -> authService.login(request));

        assertEquals("Invalid email or password.", exception.getMessage());
        verify(loginAttemptService).recordFailure("missing@test.com");
    }

    @Test
    void login_ShouldThrowUnauthorized_WhenAccountInactive() {
        User user = new User(
                "id", "John", "john@test.com", "john@test.com",
                "hashed-password", LocalDateTime.now(), false);
        LoginRequest request = new LoginRequest("john@test.com", "A-valid-local password 2026!");

        when(userRepository.findByCanonicalEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("A-valid-local password 2026!", "hashed-password")).thenReturn(true);

        UnauthorizedException exception = assertThrows(UnauthorizedException.class, () -> authService.login(request));
        assertEquals("Invalid email or password.", exception.getMessage());
    }

    @Test
    void login_ShouldRateLimitAtThreshold() {
        LoginRequest request = new LoginRequest("john@test.com", "wrong-password");
        User user = new User(
                "id", "John", "john@test.com", "john@test.com",
                "hashed-password", LocalDateTime.now(), true);
        when(userRepository.findByCanonicalEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", "hashed-password")).thenReturn(false);
        when(loginAttemptService.recordFailure("john@test.com")).thenReturn(900L);

        LoginRateLimitException exception = assertThrows(LoginRateLimitException.class,
                () -> authService.login(request));

        assertEquals(900L, exception.getRetryAfterSeconds());
    }

    @Test
    void login_ShouldStillVerifyPasswordWhenAlreadyRateLimited() {
        LoginRequest request = new LoginRequest("john@test.com", "wrong-password");
        User user = new User(
                "id", "John", "john@test.com", "john@test.com",
                "hashed-password", LocalDateTime.now(), true);
        when(loginAttemptService.retryAfterSecondsIfBlocked("john@test.com")).thenReturn(600L);
        when(userRepository.findByCanonicalEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", "hashed-password")).thenReturn(false);

        assertThrows(LoginRateLimitException.class, () -> authService.login(request));

        verify(passwordEncoder).matches("wrong-password", "hashed-password");
        verify(loginAttemptService, never()).recordFailure(anyString());
    }

    @Test
    void login_ShouldUpgradeLegacyHashAfterSuccessfulAuthentication() {
        LoginRequest request = new LoginRequest("john@test.com", "A-valid-local password 2026!");
        User user = new User(
                "id", "John", "john@test.com", "john@test.com",
                "$2a$legacy", LocalDateTime.now(), true);
        when(userRepository.findByCanonicalEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(request.getPassword(), "$2a$legacy")).thenReturn(true);
        when(passwordEncoder.encode(request.getPassword())).thenReturn("{pbkdf2}upgraded");

        authService.login(request);

        assertEquals("{pbkdf2}upgraded", user.getPasswordHash());
        verify(userRepository).save(user);
    }

    @Test
    void getUserAccount_ShouldSucceed() {
        String userId = UUID.randomUUID().toString();
        User user = new User(
                userId, "John", "john@test.com", "john@test.com",
                "hash", LocalDateTime.now(), true);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        UserAccountResponse response = authService.getUserAccount(userId);

        assertNotNull(response);
        assertEquals(userId, response.getId());
        assertEquals("John", response.getName());
        assertEquals("john@test.com", response.getEmail());
    }

    @Test
    void getUserAccount_ShouldThrowNotFound() {
        when(userRepository.findById("unknown-id")).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> authService.getUserAccount("unknown-id"));
    }

    @Test
    void returnsRegistrationLegalAcceptanceForPersonalDataExport() {
        var acceptance = new RegistrationLegalAcceptance(
                "user-123", "2026-08-15", true, true, true,
                Instant.parse("2026-08-15T00:00:00Z"));
        when(legalAcceptanceRepository.findById("user-123"))
                .thenReturn(Optional.of(acceptance));

        var response = authService.getRegistrationLegalAcceptance("user-123");

        assertEquals("2026-08-15", response.legalVersion());
        assertTrue(response.ageEligibilityConfirmed());
        assertEquals(acceptance.getAcceptedAt(), response.acceptedAt());
    }

    @Test
    void validate_ShouldReturnUserId() {
        AccessTokenClaims claims = new AccessTokenClaims("user-123", "session-123");
        when(jwtTokenProvider.parseAccessToken("valid-token")).thenReturn(claims);

        String result = authService.validate("valid-token");

        assertEquals("user-123", result);
        verify(sessionTokenService).validate(claims);
    }

    private RegisterRequest accepted(String name, String email, String password) {
        return new RegisterRequest(
                name, email, password, true, true, true, "2026-08-15");
    }
}
