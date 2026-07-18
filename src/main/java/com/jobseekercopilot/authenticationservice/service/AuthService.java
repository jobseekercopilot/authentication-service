package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.BadRequestException;
import com.jobseekercopilot.authenticationservice.exception.ConflictException;
import com.jobseekercopilot.authenticationservice.exception.ResourceNotFoundException;
import com.jobseekercopilot.authenticationservice.exception.UnauthorizedException;
import com.jobseekercopilot.authenticationservice.model.*;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

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
        long startedAt = System.nanoTime();
        log.info("Registration request validation started hasRequest={}", request != null);
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
            log.warn("Registration rejected reason=EmailAlreadyExists durationMs={}",
                    (System.nanoTime() - startedAt) / 1_000_000);
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

        User saved = userRepository.save(user);
        log.info("User registered userId={} durationMs={}",
                saved.getId(),
                (System.nanoTime() - startedAt) / 1_000_000);
    }

    public LoginResponse login(LoginRequest request) {
        long startedAt = System.nanoTime();
        log.info("Login request validation started hasRequest={}", request != null);
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
            log.warn("Login rejected userId={} reason=InvalidPassword durationMs={}",
                    user.getId(),
                    (System.nanoTime() - startedAt) / 1_000_000);
            throw new UnauthorizedException("Invalid credentials. Check password and try again.");
        }

        if (!user.isActive()) {
            log.warn("Login rejected userId={} reason=InactiveAccount durationMs={}",
                    user.getId(),
                    (System.nanoTime() - startedAt) / 1_000_000);
            throw new UnauthorizedException("Account is inactive.");
        }

        String token = jwtTokenProvider.generateToken(user.getId());
        log.info("Login succeeded userId={} durationMs={}",
                user.getId(),
                (System.nanoTime() - startedAt) / 1_000_000);
        return new LoginResponse(token);
    }

    public UserAccountResponse getUserAccount(String userId) {
        long startedAt = System.nanoTime();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        log.info("User account loaded userId={} durationMs={}",
                userId,
                (System.nanoTime() - startedAt) / 1_000_000);
        return new UserAccountResponse(user.getId(), user.getName(), user.getEmail());
    }

    public String validate(String token) {
        long startedAt = System.nanoTime();
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        try {
            String userId = jwtTokenProvider.getUserIdFromToken(token);
            log.info("JWT validation succeeded userId={} durationMs={}",
                    userId,
                    (System.nanoTime() - startedAt) / 1_000_000);
            return userId;
        } catch (Exception e) {
            log.warn("JWT validation failed durationMs={} error={}",
                    (System.nanoTime() - startedAt) / 1_000_000,
                    e.getClass().getSimpleName());
            throw new RuntimeException("Invalid or expired token", e);
        }
    }
}
