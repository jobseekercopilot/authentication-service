package com.jobseekercopilot.authenticationservice.repository;

import com.jobseekercopilot.authenticationservice.model.RegistrationLegalAcceptance;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RegistrationLegalAcceptanceRepository
        extends JpaRepository<RegistrationLegalAcceptance, String> {
}
