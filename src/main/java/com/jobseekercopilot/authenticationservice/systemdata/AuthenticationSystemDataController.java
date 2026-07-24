package com.jobseekercopilot.authenticationservice.systemdata;

import com.jobseekercopilot.authenticationservice.identity.EmailIdentityCanonicalizer;
import com.jobseekercopilot.authenticationservice.model.User;
import com.jobseekercopilot.authenticationservice.repository.UserRepository;
import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/internal/system-data")
@Hidden
public class AuthenticationSystemDataController {
    private final EnvironmentDataGuard guard;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailIdentityCanonicalizer emailCanonicalizer;

    public AuthenticationSystemDataController(
            EnvironmentDataGuard guard,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            EmailIdentityCanonicalizer emailCanonicalizer) {
        this.guard = guard;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailCanonicalizer = emailCanonicalizer;
    }

    @PostMapping("/seed/user")
    public ResponseEntity<SystemDataResult> seedUser(@RequestBody SystemDataUserRequest request) {
        guard.requireEnabled();
        var emailIdentity = emailCanonicalizer.normalize(request.email());
        userRepository.findByCanonicalEmail(emailIdentity.canonical()).ifPresent(userRepository::delete);
        User saved = userRepository.save(new User(
                request.userId(),
                request.name(),
                emailIdentity.display(),
                emailIdentity.canonical(),
                passwordEncoder.encode(request.password()),
                request.createdAt() == null ? LocalDateTime.now() : request.createdAt(),
                true));
        return ResponseEntity.ok(SystemDataResult.success(
                "SEED",
                1,
                guard.activeEnvironment(),
                Map.of("userId", saved.getId(), "email", saved.getEmail())));
    }

    @DeleteMapping("/scenario/{scenarioId}/users/{userId}")
    public ResponseEntity<SystemDataResult> resetUser(@PathVariable String scenarioId, @PathVariable String userId) {
        guard.requireEnabled();
        boolean existed = userRepository.existsById(userId);
        if (existed) {
            userRepository.deleteById(userId);
        }
        return ResponseEntity.ok(SystemDataResult.success(
                "RESET",
                existed ? 1 : 0,
                guard.activeEnvironment(),
                Map.of("scenarioId", scenarioId, "userId", userId)));
    }

    @GetMapping("/verify/users/{userId}")
    public ResponseEntity<SystemDataResult> verifyUser(@PathVariable String userId) {
        guard.requireEnabled();
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("userId", userId);
        details.put("exists", userRepository.existsById(userId));
        return ResponseEntity.ok(SystemDataResult.success("VERIFY", userRepository.existsById(userId) ? 1 : 0, guard.activeEnvironment(), details));
    }
}
