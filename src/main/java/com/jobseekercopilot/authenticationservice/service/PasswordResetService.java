package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.BadRequestException;
import com.jobseekercopilot.authenticationservice.exception.PasswordResetException;
import com.jobseekercopilot.authenticationservice.identity.EmailIdentityCanonicalizer;
import com.jobseekercopilot.authenticationservice.model.PasswordResetCompletionRequest;
import com.jobseekercopilot.authenticationservice.model.PasswordResetRequest;
import com.jobseekercopilot.authenticationservice.model.PasswordResetToken;
import com.jobseekercopilot.authenticationservice.model.User;
import com.jobseekercopilot.authenticationservice.repository.AuthenticationSessionRepository;
import com.jobseekercopilot.authenticationservice.repository.PasswordResetTokenRepository;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PasswordResetService {

    private static final int TOKEN_BYTES = 32;
    private static final int MAXIMUM_TOKEN_LENGTH = 128;
    private static final Pattern TOKEN_FORMAT = Pattern.compile("^[A-Za-z0-9_-]{32,128}$");

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final AuthenticationSessionRepository sessionRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final EmailIdentityCanonicalizer emailCanonicalizer;
    private final ApplicationEventPublisher events;
    private final Clock clock;
    private final Duration lifetime;
    private final Duration requestCooldown;
    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordResetService(
            UserRepository userRepository,
            PasswordResetTokenRepository tokenRepository,
            AuthenticationSessionRepository sessionRepository,
            PasswordEncoder passwordEncoder,
            PasswordPolicy passwordPolicy,
            EmailIdentityCanonicalizer emailCanonicalizer,
            ApplicationEventPublisher events,
            Clock clock,
            @Value("${auth.password-reset.token-lifetime:30m}") Duration lifetime,
            @Value("${auth.password-reset.request-cooldown:60s}") Duration requestCooldown) {
        if (lifetime == null || lifetime.isNegative() || lifetime.isZero()
                || lifetime.compareTo(Duration.ofHours(24)) > 0) {
            throw new IllegalStateException("Password-reset token lifetime must be between 1 second and 24 hours");
        }
        if (requestCooldown == null || requestCooldown.isNegative()
                || requestCooldown.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new IllegalStateException("Password-reset cooldown must be between 0 and 15 minutes");
        }
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.sessionRepository = sessionRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.emailCanonicalizer = emailCanonicalizer;
        this.events = events;
        this.clock = clock;
        this.lifetime = lifetime;
        this.requestCooldown = requestCooldown;
    }

    @Transactional
    public void requestReset(PasswordResetRequest request) {
        if (request == null || request.email() == null) {
            throw new BadRequestException("Email is required.");
        }
        String canonicalEmail = emailCanonicalizer.normalize(request.email()).canonical();
        if (canonicalEmail.isBlank() || canonicalEmail.length() > 254 || !canonicalEmail.contains("@")) {
            throw new BadRequestException("Enter a valid email address.");
        }

        User user = userRepository.findByCanonicalEmailForUpdate(canonicalEmail).orElse(null);
        if (user == null || !user.isActive()) {
            return;
        }

        Instant now = clock.instant();
        boolean coolingDown = tokenRepository.findTopByUserIdOrderByCreatedAtDesc(user.getId())
                .map(token -> token.getCreatedAt().plus(requestCooldown).isAfter(now))
                .orElse(false);
        if (coolingDown) {
            return;
        }

        tokenRepository.invalidateUnusedForUser(user.getId(), now);
        String rawToken = randomToken();
        Instant expiresAt = now.plus(lifetime);
        tokenRepository.save(new PasswordResetToken(
                UUID.randomUUID().toString(),
                user.getId(),
                hash(rawToken),
                now,
                expiresAt,
                null,
                null));
        events.publishEvent(new PasswordResetEmailRequested(
                user.getId(), user.getEmail(), rawToken, expiresAt));
    }

    @Transactional
    public void completeReset(PasswordResetCompletionRequest request) {
        if (request == null || request.token() == null || request.newPassword() == null
                || request.token().length() > MAXIMUM_TOKEN_LENGTH
                || !TOKEN_FORMAT.matcher(request.token()).matches()) {
            throw PasswordResetException.invalid();
        }

        PasswordResetToken token = tokenRepository.findByTokenHashForUpdate(hash(request.token()))
                .orElseThrow(PasswordResetException::invalid);
        Instant now = clock.instant();
        if (token.getConsumedAt() != null || token.getInvalidatedAt() != null
                || !now.isBefore(token.getExpiresAt())) {
            throw PasswordResetException.invalid();
        }

        User user = userRepository.findByIdForUpdate(token.getUserId())
                .filter(User::isActive)
                .orElseThrow(PasswordResetException::invalid);
        passwordPolicy.validateNewPassword(user, request.newPassword());
        if (passwordEncoder.matches(request.newPassword(), user.getPasswordHash())) {
            throw new BadRequestException("Choose a password that is different from your current password.");
        }

        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
        token.setConsumedAt(now);
        tokenRepository.save(token);
        tokenRepository.invalidateUnusedExcept(user.getId(), token.getId(), now);
        sessionRepository.revokeAllActiveForUser(user.getId(), now);
        events.publishEvent(new PasswordChanged(user.getId(), user.getEmail()));
    }

    private String randomToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
