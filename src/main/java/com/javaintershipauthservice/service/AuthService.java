package com.javaintershipauthservice.service;

import com.javaintershipauthservice.dto.request.LoginRequest;
import com.javaintershipauthservice.dto.request.RefreshTokenRequest;
import com.javaintershipauthservice.dto.request.RegisterRequest;
import com.javaintershipauthservice.dto.request.ValidateTokenRequest;
import com.javaintershipauthservice.dto.response.TokenResponse;
import com.javaintershipauthservice.dto.response.ValidateTokenResponse;

/**
 * Domain authentication operations: login, credential registration, token validation and refresh.
 */
public interface AuthService {

    /**
     * Authenticates by login and password and returns an access/refresh token pair on success.
     *
     * @throws org.springframework.security.authentication.BadCredentialsException if credentials are invalid or the user is inactive
     */
    TokenResponse login(LoginRequest request);

    /**
     * Persists a user in this auth service and assigns the default role.
     *
     * @return external user identifier ({@code userId})
     * @throws IllegalArgumentException if login or {@code userId} is already taken
     */
    Long register(RegisterRequest request);

    /**
     * Parses the given JWT and returns validity and claims (without issuing new tokens).
     */
    ValidateTokenResponse validate(ValidateTokenRequest request);

    /**
     * Issues a new token pair from a refresh token when the user is still active in the database.
     *
     * @throws org.springframework.security.authentication.BadCredentialsException if the refresh token is invalid or the user is inactive
     */
    TokenResponse refresh(RefreshTokenRequest request);
}
