CREATE TABLE account_deletion_operation (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    idempotency_key_hash VARCHAR(64) NOT NULL,
    status VARCHAR(24) NOT NULL,
    document_store_completed_at TIMESTAMP WITH TIME ZONE,
    application_tracker_completed_at TIMESTAMP WITH TIME ZONE,
    user_profile_completed_at TIMESTAMP WITH TIME ZONE,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error_code VARCHAR(96),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    retention_expires_at TIMESTAMP WITH TIME ZONE,
    operation_version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uq_account_deletion_replay
        UNIQUE (user_id, idempotency_key_hash),
    CONSTRAINT ck_account_deletion_status
        CHECK (status IN ('PENDING', 'RETRY_REQUIRED', 'COMPLETED')),
    CONSTRAINT ck_account_deletion_attempts CHECK (attempt_count >= 0),
    CONSTRAINT ck_account_deletion_completion CHECK (
        (status = 'COMPLETED'
            AND completed_at IS NOT NULL
            AND retention_expires_at IS NOT NULL
            AND document_store_completed_at IS NOT NULL
            AND application_tracker_completed_at IS NOT NULL
            AND user_profile_completed_at IS NOT NULL)
        OR (status <> 'COMPLETED'
            AND completed_at IS NULL
            AND retention_expires_at IS NULL)
    )
);

CREATE INDEX idx_account_deletion_recovery
    ON account_deletion_operation (status, updated_at);

CREATE INDEX idx_account_deletion_retention
    ON account_deletion_operation (status, retention_expires_at);
