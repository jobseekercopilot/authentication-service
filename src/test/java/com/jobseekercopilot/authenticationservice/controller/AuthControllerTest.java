package com.jobseekercopilot.authenticationservice.controller;

import com.jobseekercopilot.authenticationservice.model.LoginRequest;
import com.jobseekercopilot.authenticationservice.model.LoginResponse;
import com.jobseekercopilot.authenticationservice.model.RegisterRequest;
import com.jobseekercopilot.authenticationservice.model.RefreshRequest;
import com.jobseekercopilot.authenticationservice.model.UserAccountResponse;
import com.jobseekercopilot.authenticationservice.service.AuthService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;

    @InjectMocks
    private AuthController authController;

    @Test
    void register_ShouldReturnCreated() {
        RegisterRequest request = new RegisterRequest("John", "john@test.com", "password123");
        doNothing().when(authService).register(request);

        ResponseEntity<Map<String, String>> response = authController.register(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals("User registered successfully.", response.getBody().get("message"));
        verify(authService, times(1)).register(request);
    }

    @Test
    void login_ShouldReturnToken() {
        LoginRequest request = new LoginRequest("john@test.com", "password123");
        LoginResponse loginResponse = new LoginResponse("jwt-token");
        when(authService.login(request)).thenReturn(loginResponse);

        ResponseEntity<LoginResponse> response = authController.login(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("jwt-token", response.getBody().getToken());
        verify(authService, times(1)).login(request);
    }

    @Test
    void getCurrentUser_ShouldReturnUserAccount() {
        String authHeader = "Bearer valid-token";
        String userId = "user-123";
        UserAccountResponse account = new UserAccountResponse("user-123", "John", "john@test.com");

        when(authService.validate("valid-token")).thenReturn(userId);
        when(authService.getUserAccount(userId)).thenReturn(account);

        ResponseEntity<UserAccountResponse> response = authController.getCurrentUser(authHeader);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("user-123", response.getBody().getId());
        assertEquals("John", response.getBody().getName());
        verify(authService, times(1)).validate("valid-token");
        verify(authService, times(1)).getUserAccount(userId);
    }

    @Test
    void refreshReturnsRotatedTokenPair() {
        RefreshRequest request = new RefreshRequest("refresh-token");
        LoginResponse rotated = new LoginResponse("access", "next-refresh", "Bearer", 900);
        when(authService.refresh("refresh-token")).thenReturn(rotated);

        ResponseEntity<LoginResponse> response = authController.refresh(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("next-refresh", response.getBody().getRefreshToken());
    }

    @Test
    void logoutRevokesBearerSession() {
        ResponseEntity<Void> response = authController.logout("Bearer access-token");

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(authService).logout("access-token");
    }
}
