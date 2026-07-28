package com.jobseekercopilot.authenticationservice.repository;

import com.jobseekercopilot.authenticationservice.model.AuthenticationSession;
import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuthenticationSessionRepository extends JpaRepository<AuthenticationSession, String> {

    @Modifying
    @Query("""
            update AuthenticationSession session
               set session.revokedAt = :now
             where session.userId = :userId
               and session.revokedAt is null
            """)
    int revokeAllActiveForUser(@Param("userId") String userId, @Param("now") Instant now);
}
