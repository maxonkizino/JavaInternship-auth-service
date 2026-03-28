package com.javaintershipauthservice.controller;

import com.javaintershipauthservice.dto.request.LoginRequest;
import com.javaintershipauthservice.dto.request.RefreshTokenRequest;
import com.javaintershipauthservice.dto.request.RegisterRequest;
import com.javaintershipauthservice.dto.request.ValidateTokenRequest;
import com.javaintershipauthservice.dto.response.TokenResponse;
import com.javaintershipauthservice.dto.response.ValidateTokenResponse;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Public authentication API: login, credential registration, token validation and refresh, CSRF.
 * All endpoints allow anonymous access via {@code @PreAuthorize("permitAll()")}.
 */
@PreAuthorize("permitAll()")
@RequestMapping("/auth")
public interface AuthApi {

    /**
     * Issues an access/refresh JWT pair for the given login and password.
     */
    @PostMapping("/login")
    TokenResponse login(@Valid @RequestBody LoginRequest request);

    /**
     * Registers credentials in this auth service (links external {@code userId} to login/password).
     */
    @PostMapping("/credentials")
    Long register(@Valid @RequestBody RegisterRequest request);

    /**
     * Validates a JWT and returns claims without issuing new tokens.
     */
    @PostMapping("/validate")
    ValidateTokenResponse validate(@Valid @RequestBody ValidateTokenRequest request);

    /**
     * Rotates the token pair using a valid refresh token.
     */
    @PostMapping("/refresh")
    TokenResponse refresh(@Valid @RequestBody RefreshTokenRequest request);

    /**
     * Returns the current CSRF token for clients using cookie-based CSRF protection.
     */
    @GetMapping("/csrf")
    CsrfToken csrf(CsrfToken csrfToken);
}
