package com.jobseekercopilot.authenticationservice.repository;

import com.jobseekercopilot.authenticationservice.model.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByCanonicalEmail(String canonicalEmail);
    Optional<User> findById(String id);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select user from User user where user.canonicalEmail = :canonicalEmail")
    Optional<User> findByCanonicalEmailForUpdate(@Param("canonicalEmail") String canonicalEmail);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select user from User user where user.id = :id")
    Optional<User> findByIdForUpdate(@Param("id") String id);
}
