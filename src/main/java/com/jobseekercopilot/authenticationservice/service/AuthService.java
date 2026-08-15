package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.ConflictException;
import com.jobseekercopilot.authenticationservice.exception.LoginRateLimitException;
import com.jobseekercopilot.authenticationservice.exception.ResourceNotFoundException;
import com.jobseekercopilot.authenticationservice.exception.UnauthorizedException;
import com.jobseekercopilot.authenticationservice.exception.TokenValidationException;
import com.jobseekercopilot.authenticationservice.identity.EmailIdentityCanonicalizer;
import com.jobseekercopilot.authenticationservice.model.*;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import com.jobseekercopilot.authenticationservice.repository.RegistrationLegalAcceptanceRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.Duration;
import java.util.UUID;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private static final String INVALID_CREDENTIALS = "Invalid email or password.";
    private static final String DUMMY_PASSWORD = "authentication-timing-placeholder";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordPolicy passwordPolicy;
    private final LoginAttemptService loginAttemptService;
    private final EmailIdentityCanonicalizer emailCanonicalizer;
    private final SessionTokenService sessionTokenService;
    private final LegalAcceptancePolicy legalAcceptancePolicy;
    private final RegistrationLegalAcceptanceRepository legalAcceptanceRepository;
    private final String dummyPasswordHash;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenProvider jwtTokenProvider,
            PasswordPolicy passwordPolicy,
            LoginAttemptService loginAttemptService,
            EmailIdentityCanonicalizer emailCanonicalizer,
            SessionTokenService sessionTokenService,
            LegalAcceptancePolicy legalAcceptancePolicy,
            RegistrationLegalAcceptanceRepository legalAcceptanceRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.passwordPolicy = passwordPolicy;
        this.loginAttemptService = loginAttemptService;
        this.emailCanonicalizer = emailCanonicalizer;
        this.sessionTokenService = sessionTokenService;
        this.legalAcceptancePolicy = legalAcceptancePolicy;
        this.legalAcceptanceRepository = legalAcceptanceRepository;
        this.dummyPasswordHash = passwordEncoder.encode(DUMMY_PASSWORD);
    }

    @Transactional
    public void register(RegisterRequest request) {
        long startedAt = System.nanoTime();
        log.info("Registration request validation started hasRequest={}", request != null);
        passwordPolicy.validateRegistration(request);
        legalAcceptancePolicy.requireAccepted(request);

        String name = request.getName().trim();
        var emailIdentity = emailCanonicalizer.normalize(request.getEmail());
        String password = request.getPassword();

        if (userRepository.findByCanonicalEmail(emailIdentity.canonical()).isPresent()) {
            log.warn("Registration rejected reason=EmailAlreadyExists durationMs={}",
                    (System.nanoTime() - startedAt) / 1_000_000);
            throw new ConflictException("An account with this email already exists.");
        }

        String hashedPassword = passwordEncoder.encode(password);
        User user = new User(
                UUID.randomUUID().toString(),
                name,
                emailIdentity.display(),
                emailIdentity.canonical(),
                hashedPassword,
                LocalDateTime.now(),
                true
        );

        User saved;
        try {
            saved = userRepository.save(user);
        } catch (DataIntegrityViolationException exception) {
            log.warn("Registration rejected reason=IdentityConstraintConflict durationMs={}",
                    (System.nanoTime() - startedAt) / 1_000_000);
            throw new ConflictException("An account with this email already exists.");
        }
        legalAcceptanceRepository.save(
                legalAcceptancePolicy.acceptanceFor(saved.getId()));
        log.info("User registered userId={} durationMs={}",
                saved.getId(),
                (System.nanoTime() - startedAt) / 1_000_000);
    }

    public RegistrationLegalAcceptanceResponse getRegistrationLegalAcceptance(
            String userId) {
        return legalAcceptanceRepository.findById(userId)
                .map(RegistrationLegalAcceptanceResponse::from)
                .orElse(null);
    }

    public RegistrationLegalRequirements getRegistrationLegalRequirements() {
        return legalAcceptancePolicy.requirements();
    }

    public LoginResponse login(LoginRequest request) {
        long startedAt = System.nanoTime();
        log.info("Login request validation started hasRequest={}", request != null);
        String email = emailCanonicalizer.normalize(
                request == null ? null : request.getEmail()).canonical();
        String password = request == null || request.getPassword() == null ? "" : request.getPassword();

        long retryAfter = loginAttemptService.retryAfterSecondsIfBlocked(email);
        var user = email.isEmpty()
                ? java.util.Optional.<User>empty()
                : userRepository.findByCanonicalEmail(email);
        String storedHash = user.map(User::getPasswordHash).orElse(dummyPasswordHash);
        boolean passwordMatches = passwordEncoder.matches(password, storedHash);

        if (retryAfter > 0) {
            log.warn("Login rate limited durationMs={}", (System.nanoTime() - startedAt) / 1_000_000);
            throw new LoginRateLimitException(retryAfter);
        }

        if (user.isEmpty() || !passwordMatches || !user.get().isActive()) {
            long blockedFor = loginAttemptService.recordFailure(email);
            log.warn("Login rejected reason=InvalidCredentials durationMs={}",
                    (System.nanoTime() - startedAt) / 1_000_000);
            if (blockedFor > 0) {
                throw new LoginRateLimitException(blockedFor);
            }
            throw new UnauthorizedException(INVALID_CREDENTIALS);
        }

        User authenticatedUser = user.get();
        loginAttemptService.recordSuccess(email);
        if (!storedHash.startsWith("{") || passwordEncoder.upgradeEncoding(storedHash)) {
            authenticatedUser.setPasswordHash(passwordEncoder.encode(password));
            userRepository.save(authenticatedUser);
        }

        log.info("Login succeeded userId={} durationMs={}",
                authenticatedUser.getId(),
                (System.nanoTime() - startedAt) / 1_000_000);
        return sessionTokenService.issue(authenticatedUser.getId());
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
            throw TokenValidationException.required();
        }

        try {
            AccessTokenClaims claims = jwtTokenProvider.parseAccessToken(token);
            sessionTokenService.validate(claims);
            log.info("JWT validation succeeded userId={} durationMs={}",
                    claims.userId(),
                    (System.nanoTime() - startedAt) / 1_000_000);
            return claims.userId();
        } catch (ExpiredJwtException exception) {
            return rejectToken(startedAt, exception, TokenValidationException.expired());
        } catch (MalformedJwtException exception) {
            return rejectToken(startedAt, exception, TokenValidationException.malformed());
        } catch (UnsupportedJwtException exception) {
            return rejectToken(startedAt, exception, TokenValidationException.unsupported());
        } catch (SecurityException exception) {
            return rejectToken(startedAt, exception, TokenValidationException.invalid());
        } catch (JwtException | IllegalArgumentException exception) {
            return rejectToken(startedAt, exception, TokenValidationException.invalid());
        }
    }

    public String validateRecentlyAuthenticated(String token, Duration maximumAge) {
        long startedAt = System.nanoTime();
        if (token == null || token.trim().isEmpty()) {
            throw TokenValidationException.required();
        }
        try {
            AccessTokenClaims claims = jwtTokenProvider.parseAccessToken(token);
            sessionTokenService.validateRecent(claims, maximumAge);
            log.info("Recent authentication validated userId={} durationMs={}",
                    claims.userId(),
                    (System.nanoTime() - startedAt) / 1_000_000);
            return claims.userId();
        } catch (ExpiredJwtException exception) {
            return rejectToken(startedAt, exception, TokenValidationException.expired());
        } catch (MalformedJwtException exception) {
            return rejectToken(startedAt, exception, TokenValidationException.malformed());
        } catch (UnsupportedJwtException exception) {
            return rejectToken(startedAt, exception, TokenValidationException.unsupported());
        } catch (SecurityException exception) {
            return rejectToken(startedAt, exception, TokenValidationException.invalid());
        } catch (JwtException | IllegalArgumentException exception) {
            return rejectToken(startedAt, exception, TokenValidationException.invalid());
        }
    }

    public LoginResponse refresh(String refreshToken) {
        return sessionTokenService.rotate(refreshToken);
    }

    public void logout(String token) {
        if (token == null || token.isBlank()) {
            throw TokenValidationException.required();
        }
        try {
            sessionTokenService.revoke(jwtTokenProvider.parseAccessToken(token));
        } catch (ExpiredJwtException exception) {
            throw TokenValidationException.expired();
        } catch (JwtException | IllegalArgumentException exception) {
            throw TokenValidationException.invalid();
        }
    }

    private String rejectToken(long startedAt, Exception cause, TokenValidationException safeException) {
        log.warn("JWT validation failed durationMs={} error={}",
                (System.nanoTime() - startedAt) / 1_000_000,
                cause.getClass().getSimpleName());
        throw safeException;
    }
}
