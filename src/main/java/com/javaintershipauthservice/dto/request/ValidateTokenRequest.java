package com.javaintershipauthservice.dto.request;

import jakarta.validation.constraints.NotBlank;

public record ValidateTokenRequest(
        @NotBlank String token
) {
}

