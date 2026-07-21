package com.jobseekercopilot.authenticationservice.controller;

import com.jobseekercopilot.authenticationservice.service.JwtTokenProvider;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksController {

    private final JwtTokenProvider tokenProvider;

    public JwksController(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @GetMapping("/.well-known/jwks.json")
    @Operation(summary = "Get public access-token verification keys",
            description = "Returns active and rotation-overlap RSA public keys in JWKS format.")
    @Tag(name = "Token verification")
    public ResponseEntity<Map<String, List<Map<String, String>>>> keys() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic().mustRevalidate())
                .body(Map.of("keys", tokenProvider.getJsonWebKeys()));
    }
}
