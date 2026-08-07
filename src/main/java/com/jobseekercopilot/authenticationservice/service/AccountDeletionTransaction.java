package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.ResourceNotFoundException;
import com.jobseekercopilot.authenticationservice.exception.BadRequestException;
import com.jobseekercopilot.authenticationservice.model.AccountDeletionOperation;
import com.jobseekercopilot.authenticationservice.model.AccountDeletionStatus;
import com.jobseekercopilot.authenticationservice.repository.AccountDeletionOperationRepository;
import com.jobseekercopilot.authenticationservice.repository.AuthenticationSessionRepository;
import com.jobseekercopilot.authenticationservice.repository.PasswordResetTokenRepository;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AccountDeletionTransaction {

    private static final Pattern IDEMPOTENCY_KEY =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{15,127}");

    private final AccountDeletionOperationRepository operationRepository;
    private final UserRepository userRepository;
    private final AuthenticationSessionRepository sessionRepository;
    private final PasswordResetTokenRepository resetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;

    @Transactional
    public AccountDeletionOperation start(String userId, String idempotencyKey) {
        String normalizedKey = requireIdempotencyKey(idempotencyKey);
        String keyHash = SessionTokenService.hash(normalizedKey);
        AccountDeletionOperation replay = operationRepository
                .findByUserIdAndIdempotencyKeyHash(userId, keyHash)
                .orElse(null);
        if (replay != null) {
            return replay;
        }

        var user = userRepository.findByIdForUpdate(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        replay = operationRepository
                .findByUserIdAndIdempotencyKeyHash(userId, keyHash)
                .orElse(null);
        if (replay != null) {
            return replay;
        }
        if (!user.isActive()) {
            throw new ResourceNotFoundException("User not found");
        }

        var now = clock.instant();
        var operation = new AccountDeletionOperation(
                UUID.randomUUID().toString(),
                userId,
                keyHash,
                AccountDeletionStatus.PENDING,
                null,
                null,
                null,
                0,
                null,
                now,
                now,
                null,
                null,
                0L);
        operationRepository.save(operation);

        user.setActive(false);
        user.setName("Deleted account");
        String deletedEmail = "deleted+" + userId + "@invalid.jobseekercopilot";
        user.setEmail(deletedEmail);
        user.setCanonicalEmail(deletedEmail);
        user.setPasswordHash(passwordEncoder.encode(UUID.randomUUID().toString()));
        userRepository.save(user);
        resetTokenRepository.deleteByUserId(userId);
        sessionRepository.deleteByUserId(userId);
        operationRepository.flush();
        return operation;
    }

    @Transactional(readOnly = true)
    public AccountDeletionOperation get(String operationId) {
        return operationRepository.findById(operationId)
                .orElseThrow(() -> new ResourceNotFoundException("Deletion operation not found"));
    }

    @Transactional
    public AccountDeletionOperation markStep(String operationId, Step step) {
        AccountDeletionOperation operation = operationRepository.findByIdForUpdate(operationId)
                .orElseThrow(() -> new ResourceNotFoundException("Deletion operation not found"));
        var now = clock.instant();
        if (step == Step.DOCUMENT_STORE && operation.getDocumentStoreCompletedAt() == null) {
            operation.setDocumentStoreCompletedAt(now);
        } else if (step == Step.APPLICATION_TRACKER
                && operation.getApplicationTrackerCompletedAt() == null) {
            operation.setApplicationTrackerCompletedAt(now);
        } else if (step == Step.USER_PROFILE
                && operation.getUserProfileCompletedAt() == null) {
            operation.setUserProfileCompletedAt(now);
        }
        operation.setStatus(AccountDeletionStatus.PENDING);
        operation.setLastErrorCode(null);
        operation.setUpdatedAt(now);
        return operationRepository.save(operation);
    }

    @Transactional
    public AccountDeletionOperation markFailure(String operationId, String errorCode) {
        AccountDeletionOperation operation = operationRepository.findByIdForUpdate(operationId)
                .orElseThrow(() -> new ResourceNotFoundException("Deletion operation not found"));
        if (operation.getStatus() == AccountDeletionStatus.COMPLETED) {
            return operation;
        }
        operation.setStatus(AccountDeletionStatus.RETRY_REQUIRED);
        operation.setAttemptCount(operation.getAttemptCount() + 1);
        operation.setLastErrorCode(safeErrorCode(errorCode));
        operation.setUpdatedAt(clock.instant());
        return operationRepository.save(operation);
    }

    @Transactional
    public AccountDeletionOperation complete(String operationId, Duration retention) {
        AccountDeletionOperation operation = operationRepository.findByIdForUpdate(operationId)
                .orElseThrow(() -> new ResourceNotFoundException("Deletion operation not found"));
        if (operation.getStatus() == AccountDeletionStatus.COMPLETED) {
            return operation;
        }
        if (operation.getDocumentStoreCompletedAt() == null
                || operation.getApplicationTrackerCompletedAt() == null
                || operation.getUserProfileCompletedAt() == null) {
            throw new IllegalStateException("Deletion cannot complete before every service step");
        }
        var now = clock.instant();
        userRepository.findById(operation.getUserId()).ifPresent(userRepository::delete);
        operation.setStatus(AccountDeletionStatus.COMPLETED);
        operation.setCompletedAt(now);
        operation.setRetentionExpiresAt(now.plus(retention));
        operation.setUpdatedAt(now);
        operation.setLastErrorCode(null);
        return operationRepository.save(operation);
    }

    @Transactional(readOnly = true)
    public List<AccountDeletionOperation> unresolved(int batchSize) {
        return operationRepository.findByStatusNotOrderByUpdatedAtAsc(
                AccountDeletionStatus.COMPLETED,
                PageRequest.of(0, batchSize));
    }

    @Transactional
    public int removeExpiredCompleted() {
        return operationRepository.deleteExpiredCompleted(
                AccountDeletionStatus.COMPLETED, clock.instant());
    }

    private String requireIdempotencyKey(String key) {
        if (key == null || !IDEMPOTENCY_KEY.matcher(key).matches()) {
            throw new BadRequestException(
                    "Idempotency-Key must be 16-128 URL-safe ASCII characters");
        }
        return key;
    }

    private String safeErrorCode(String code) {
        if (code == null || !code.matches("[A-Z0-9_]{1,96}")) {
            return "DOWNSTREAM_FAILED";
        }
        return code;
    }

    public enum Step {
        DOCUMENT_STORE,
        APPLICATION_TRACKER,
        USER_PROFILE
    }
}
