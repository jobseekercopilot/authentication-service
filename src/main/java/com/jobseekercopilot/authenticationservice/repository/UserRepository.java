package com.jobseekercopilot.authenticationservice.repository;

import com.jobseekercopilot.authenticationservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByCanonicalEmail(String canonicalEmail);
    Optional<User> findById(String id);
}
