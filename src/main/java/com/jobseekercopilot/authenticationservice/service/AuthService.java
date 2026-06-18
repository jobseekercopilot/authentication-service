package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.BadRequestException;
import com.jobseekercopilot.authenticationservice.exception.ConflictException;
import com.jobseekercopilot.authenticationservice.exception.ResourceNotFoundException;
import com.jobseekercopilot.authenticationservice.exception.UnauthorizedException;
import com.jobseekercopilot.authenticationservice.model.*;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthService(
            UserRepository userRepository,
            BCryptPasswordEncoder passwordEncoder,
            JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public void register(RegisterRequest request) {
        if (request == null || request.getEmail() == null || request.getPassword() == null) {
            throw new BadRequestException("Missing email or password.");
        }

        String name = request.getName();
        String email = request.getEmail().trim();
        String password = request.getPassword();

        if (email.isEmpty() || password.isEmpty() || name.isEmpty()) {
            throw new BadRequestException("Email, name or password cannot be empty.");
        }

        if (!email.contains("@")) {
            throw new BadRequestException("Invalid email format.");
        }

        if (password.length() < 4) {
            throw new BadRequestException("Password must be at least 4 characters long.");
        }

        if (userRepository.findByEmail(email).isPresent()) {
            throw new ConflictException("An account with this email already exists.");
        }

        String hashedPassword = passwordEncoder.encode(password);
        User user = new User(
                UUID.randomUUID().toString(),
                name,
                email,
                hashedPassword,
                LocalDateTime.now(),
                true
        );

        userRepository.save(user);
    }

    public LoginResponse login(LoginRequest request) {
        if (request == null || request.getEmail() == null || request.getPassword() == null) {
            throw new BadRequestException("Missing email or password.");
        }

        String email = request.getEmail().trim();
        String password = request.getPassword();

        if (email.isEmpty() || password.isEmpty()) {
            throw new BadRequestException("Email and password cannot be empty.");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UnauthorizedException("Invalid credentials. Check email and try again."));

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new UnauthorizedException("Invalid credentials. Check password and try again.");
        }

        if (!user.isActive()) {
            throw new UnauthorizedException("Account is inactive.");
        }

        String token = jwtTokenProvider.generateToken(user.getId());
        return new LoginResponse(token);
    }

    public UserAccountResponse getUserAccount(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        return new UserAccountResponse(user.getId(), user.getName(), user.getEmail());
    }

    public String validate(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        try {
            return jwtTokenProvider.getUserIdFromToken(token);
        } catch (Exception e) {
            throw new RuntimeException("Invalid or expired token", e);
        }
    }
}
