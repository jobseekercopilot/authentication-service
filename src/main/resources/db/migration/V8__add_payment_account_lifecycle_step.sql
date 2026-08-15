ALTER TABLE account_deletion_operation
    ADD COLUMN payment_service_completed_at TIMESTAMP WITH TIME ZONE;

ALTER TABLE account_deletion_operation
    ADD COLUMN payment_service_required BOOLEAN NOT NULL DEFAULT TRUE;

-- Operations completed before Payment joined the coordinator cannot be replayed:
-- their account rows and credentials are already gone. Preserve that historical
-- fact explicitly instead of pretending a provider-reconciliation call occurred.
UPDATE account_deletion_operation
   SET payment_service_required = FALSE
 WHERE status = 'COMPLETED';

ALTER TABLE account_deletion_operation
    DROP CONSTRAINT ck_account_deletion_completion;

ALTER TABLE account_deletion_operation
    ADD CONSTRAINT ck_account_deletion_completion CHECK (
        (status = 'COMPLETED'
            AND completed_at IS NOT NULL
            AND retention_expires_at IS NOT NULL
            AND (payment_service_required = FALSE
                OR payment_service_completed_at IS NOT NULL)
            AND document_store_completed_at IS NOT NULL
            AND application_tracker_completed_at IS NOT NULL
            AND user_profile_completed_at IS NOT NULL)
        OR (status <> 'COMPLETED'
            AND completed_at IS NULL
            AND retention_expires_at IS NULL)
    );
