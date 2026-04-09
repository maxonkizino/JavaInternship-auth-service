package com.javaintershipauthservice.dto.response;

public record TokenResponse(
        String accessToken,
        String refreshToken
) {
}

