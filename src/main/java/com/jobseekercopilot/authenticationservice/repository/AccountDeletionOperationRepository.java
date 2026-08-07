package com.jobseekercopilot.authenticationservice.repository;

import com.jobseekercopilot.authenticationservice.model.AccountDeletionOperation;
import com.jobseekercopilot.authenticationservice.model.AccountDeletionStatus;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AccountDeletionOperationRepository
        extends JpaRepository<AccountDeletionOperation, String> {

    Optional<AccountDeletionOperation> findByUserIdAndIdempotencyKeyHash(
            String userId, String idempotencyKeyHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select operation from AccountDeletionOperation operation where operation.id = :id")
    Optional<AccountDeletionOperation> findByIdForUpdate(@Param("id") String id);

    List<AccountDeletionOperation> findByStatusNotOrderByUpdatedAtAsc(
            AccountDeletionStatus status, Pageable pageable);

    @Modifying
    @Query("""
            delete from AccountDeletionOperation operation
             where operation.status = :status
               and operation.retentionExpiresAt < :cutoff
            """)
    int deleteExpiredCompleted(
            @Param("status") AccountDeletionStatus status,
            @Param("cutoff") Instant cutoff);
}
