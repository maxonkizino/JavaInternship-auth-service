package com.javaintershipauthservice.dto.response;

import com.javaintershipauthservice.model.Roles;

import java.time.Instant;

public record ValidateTokenResponse(
        boolean valid,
        Long userId,
        Roles role,
        String type,
        Instant expiresAt
) {
}

