package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.BadRequestException;
import com.jobseekercopilot.authenticationservice.exception.ConflictException;
import com.jobseekercopilot.authenticationservice.exception.ResourceNotFoundException;
import com.jobseekercopilot.authenticationservice.exception.UnauthorizedException;
import com.jobseekercopilot.authenticationservice.model.*;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

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
    private BCryptPasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @InjectMocks
    private AuthService authService;

    @Test
    void register_ShouldSucceed() {
        RegisterRequest request = new RegisterRequest("John", "john@test.com", "password123");
        when(userRepository.findByEmail("john@test.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("password123")).thenReturn("hashed-password");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        assertDoesNotThrow(() -> authService.register(request));

        verify(userRepository, times(1)).findByEmail("john@test.com");
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void register_ShouldThrowBadRequest_WhenEmailMissing() {
        RegisterRequest request = new RegisterRequest("John", "", "password123");

        assertThrows(BadRequestException.class, () -> authService.register(request));
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_ShouldThrowConflict_WhenEmailExists() {
        RegisterRequest request = new RegisterRequest("John", "existing@test.com", "password123");
        when(userRepository.findByEmail("existing@test.com")).thenReturn(Optional.of(new User()));

        assertThrows(ConflictException.class, () -> authService.register(request));
        verify(userRepository, never()).save(any());
    }

    @Test
    void login_ShouldSucceed() {
        String userId = UUID.randomUUID().toString();
        User user = new User(userId, "John", "john@test.com", "hashed-password", LocalDateTime.now(), true);
        LoginRequest request = new LoginRequest("john@test.com", "password123");

        when(userRepository.findByEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("password123", "hashed-password")).thenReturn(true);
        when(jwtTokenProvider.generateToken(userId)).thenReturn("jwt-token");

        LoginResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("jwt-token", response.getToken());
    }

    @Test
    void login_ShouldThrowUnauthorized_WhenInvalidPassword() {
        User user = new User("id", "John", "john@test.com", "hashed-password", LocalDateTime.now(), true);
        LoginRequest request = new LoginRequest("john@test.com", "wrong-password");

        when(userRepository.findByEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", "hashed-password")).thenReturn(false);

        assertThrows(UnauthorizedException.class, () -> authService.login(request));
    }

    @Test
    void login_ShouldThrowUnauthorized_WhenAccountInactive() {
        User user = new User("id", "John", "john@test.com", "hashed-password", LocalDateTime.now(), false);
        LoginRequest request = new LoginRequest("john@test.com", "password123");

        when(userRepository.findByEmail("john@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("password123", "hashed-password")).thenReturn(true);

        assertThrows(UnauthorizedException.class, () -> authService.login(request));
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