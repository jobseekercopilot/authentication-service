package com.jobseekercopilot.authenticationservice.repository;

import com.jobseekercopilot.authenticationservice.model.PasswordResetToken;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, String> {

    void deleteByUserId(String userId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select token from PasswordResetToken token where token.tokenHash = :tokenHash")
    Optional<PasswordResetToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    Optional<PasswordResetToken> findTopByUserIdOrderByCreatedAtDesc(String userId);

    @Modifying
    @Query("""
            update PasswordResetToken token
               set token.invalidatedAt = :now
             where token.userId = :userId
               and token.consumedAt is null
               and token.invalidatedAt is null
            """)
    int invalidateUnusedForUser(@Param("userId") String userId, @Param("now") Instant now);

    @Modifying
    @Query("""
            update PasswordResetToken token
               set token.invalidatedAt = :now
             where token.userId = :userId
               and token.id <> :tokenId
               and token.consumedAt is null
               and token.invalidatedAt is null
            """)
    int invalidateUnusedExcept(
            @Param("userId") String userId,
            @Param("tokenId") String tokenId,
            @Param("now") Instant now);
}
