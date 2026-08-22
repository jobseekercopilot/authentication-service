package com.jobseekercopilot.authenticationservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "account_deletion_operation")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AccountDeletionOperation {

    @Id
    @Column(name = "id", length = 36)
    private String id;

    @Column(name = "user_id", nullable = false, length = 36)
    private String userId;

    @Column(name = "idempotency_key_hash", nullable = false, length = 64)
    private String idempotencyKeyHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 24)
    private AccountDeletionStatus status;

    @Column(name = "document_store_completed_at")
    private Instant documentStoreCompletedAt;

    @Column(name = "payment_service_completed_at")
    private Instant paymentServiceCompletedAt;

    @Column(name = "payment_service_required", nullable = false)
    private boolean paymentServiceRequired = true;

    @Column(name = "application_tracker_completed_at")
    private Instant applicationTrackerCompletedAt;

    @Column(name = "user_profile_completed_at")
    private Instant userProfileCompletedAt;

    @Column(name = "attempt_count", nullable = false)
    private int attemptCount;

    @Column(name = "last_error_code", length = 96)
    private String lastErrorCode;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "retention_expires_at")
    private Instant retentionExpiresAt;

    @Version
    @Column(name = "operation_version", nullable = false)
    private long version;
}
