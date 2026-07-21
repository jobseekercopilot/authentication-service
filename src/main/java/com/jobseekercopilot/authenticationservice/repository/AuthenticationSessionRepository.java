package com.jobseekercopilot.authenticationservice.repository;

import com.jobseekercopilot.authenticationservice.model.AuthenticationSession;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthenticationSessionRepository extends JpaRepository<AuthenticationSession, String> {
}
