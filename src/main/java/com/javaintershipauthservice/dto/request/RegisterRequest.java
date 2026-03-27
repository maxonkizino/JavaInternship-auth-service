package com.javaintershipauthservice.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record RegisterRequest(
        @NotNull Long userId,
        @NotBlank String login,
        @NotBlank String password,
        @Email @NotBlank String email
) {
}

