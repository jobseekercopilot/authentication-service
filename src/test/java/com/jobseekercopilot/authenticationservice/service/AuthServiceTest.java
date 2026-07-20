package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.ConflictException;
import com.jobseekercopilot.authenticationservice.exception.LoginRateLimitException;
import com.jobseekercopilot.authenticationservice.exception.ResourceNotFoundException;
import com.jobseekercopilot.authenticationservice.exception.UnauthorizedException;
import com.jobseekercopilot.authenticationservice.model.*;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.junit.jupiter.api.BeforeEach;

import java.time.LocalDateTime;
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

    private AuthService authService;

    @BeforeEach
    void setUp() {
        when(passwordEncoder.encode("authentication-timing-placeholder")).thenReturn("dummy-hash");
        authService = new AuthService(userRepository, passwordEncoder, jwtTokenProvider,
                passwordPolicy, loginAttemptService);
    }

    @Test
    void register_ShouldSucceed() {
        RegisterRequest request = new RegisterRequest("John", "john@test.com", "A-valid-local password 2026!");
        when(userRepository.findByEmail("john@test.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("A-valid-local password 2026!")).thenReturn("hashed-password");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        assertDoesNotThrow(() -> authService.register(request));

        verify(userRepository, times(1)).findByEmail("john@test.com");
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void register_ShouldThrowConflict_WhenEmailExists() {
        RegisterRequest request = new RegisterRequest("John", "existing@test.com", "A-valid-local password 2026!");
        when(userRepository.findByEmail("existing@test.com")).thenReturn(Optional.of(new User()));

        assertThrows(ConflictException.class, () -> authService.register(request));
        verify(userRepository, never()).save(any());
    }

    @Test
    void login_ShouldSucceed() {
        String userId = UUID.randomUUID().toString();
        User user = new User(userId, "John", "john@test.com", "hashed-password", LocalDateTime.now(), true);
        LoginRequest request = new LoginRequest("john@test.com", "A-valid-local password 2026!");

        when(userRepository.findByEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("A-valid-local password 2026!", "hashed-password")).thenReturn(true);
        when(jwtTokenProvider.generateToken(userId)).thenReturn("jwt-token");

        LoginResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("jwt-token", response.getToken());
        verify(loginAttemptService).recordSuccess("john@test.com");
    }

    @Test
    void login_ShouldThrowUnauthorized_WhenInvalidPassword() {
        User user = new User("id", "John", "john@test.com", "hashed-password", LocalDateTime.now(), true);
        LoginRequest request = new LoginRequest("john@test.com", "wrong-password");

        when(userRepository.findByEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", "hashed-password")).thenReturn(false);

        UnauthorizedException exception = assertThrows(UnauthorizedException.class, () -> authService.login(request));
        assertEquals("Invalid email or password.", exception.getMessage());
        verify(loginAttemptService).recordFailure("john@test.com");
    }

    @Test
    void login_ShouldUseSameFailureForUnknownUser() {
        LoginRequest request = new LoginRequest("missing@test.com", "wrong-password");
        when(userRepository.findByEmail("missing@test.com")).thenReturn(Optional.empty());
        when(passwordEncoder.matches("wrong-password", "dummy-hash")).thenReturn(false);

        UnauthorizedException exception = assertThrows(UnauthorizedException.class, () -> authService.login(request));

        assertEquals("Invalid email or password.", exception.getMessage());
        verify(loginAttemptService).recordFailure("missing@test.com");
    }

    @Test
    void login_ShouldThrowUnauthorized_WhenAccountInactive() {
        User user = new User("id", "John", "john@test.com", "hashed-password", LocalDateTime.now(), false);
        LoginRequest request = new LoginRequest("john@test.com", "A-valid-local password 2026!");

        when(userRepository.findByEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("A-valid-local password 2026!", "hashed-password")).thenReturn(true);

        UnauthorizedException exception = assertThrows(UnauthorizedException.class, () -> authService.login(request));
        assertEquals("Invalid email or password.", exception.getMessage());
    }

    @Test
    void login_ShouldRateLimitAtThreshold() {
        LoginRequest request = new LoginRequest("john@test.com", "wrong-password");
        User user = new User("id", "John", "john@test.com", "hashed-password", LocalDateTime.now(), true);
        when(userRepository.findByEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", "hashed-password")).thenReturn(false);
        when(loginAttemptService.recordFailure("john@test.com")).thenReturn(900L);

        LoginRateLimitException exception = assertThrows(LoginRateLimitException.class,
                () -> authService.login(request));

        assertEquals(900L, exception.getRetryAfterSeconds());
    }

    @Test
    void login_ShouldStillVerifyPasswordWhenAlreadyRateLimited() {
        LoginRequest request = new LoginRequest("john@test.com", "wrong-password");
        User user = new User("id", "John", "john@test.com", "hashed-password", LocalDateTime.now(), true);
        when(loginAttemptService.retryAfterSecondsIfBlocked("john@test.com")).thenReturn(600L);
        when(userRepository.findByEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", "hashed-password")).thenReturn(false);

        assertThrows(LoginRateLimitException.class, () -> authService.login(request));

        verify(passwordEncoder).matches("wrong-password", "hashed-password");
        verify(loginAttemptService, never()).recordFailure(anyString());
    }

    @Test
    void login_ShouldUpgradeLegacyHashAfterSuccessfulAuthentication() {
        LoginRequest request = new LoginRequest("john@test.com", "A-valid-local password 2026!");
        User user = new User("id", "John", "john@test.com", "$2a$legacy", LocalDateTime.now(), true);
        when(userRepository.findByEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(request.getPassword(), "$2a$legacy")).thenReturn(true);
        when(passwordEncoder.encode(request.getPassword())).thenReturn("{pbkdf2}upgraded");

        authService.login(request);

        assertEquals("{pbkdf2}upgraded", user.getPasswordHash());
        verify(userRepository).save(user);
    }

    @Test
    void getUserAccount_ShouldSucceed() {
        String userId = UUID.randomUUID().toString();
        User user = new User(userId, "John", "john@test.com", "hash", LocalDateTime.now(), true);

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
    void validate_ShouldReturnUserId() {
        when(jwtTokenProvider.getUserIdFromToken("valid-token")).thenReturn("user-123");

        String result = authService.validate("valid-token");

        assertEquals("user-123", result);
    }
}
