package com.jobseekercopilot.authenticationservice.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    private String token;
    private String refreshToken;
    private String tokenType;
    private long expiresIn;

    public LoginResponse(String token) {
        this(token, null, "Bearer", 0);
    }
}
