package com.javaintershipauthservice.service;

import com.javaintershipauthservice.model.Roles;
import com.javaintershipauthservice.security.JwtTokenType;

import java.time.Instant;

/**
 * JWT creation, parsing, and validation for access and refresh tokens.
 */
public interface JwtService {

    /**
     * Parsed token claims: external {@code userId}, role, type, and lifetime.
     */
    record JwtPayload(Long userId, Roles role, JwtTokenType type, Instant issuedAt, Instant expiresAt) {
    }

    /**
     * Builds an access token using configured expiration.
     */
    String generateAccessToken(Long userId, Roles role);

    /**
     * Builds a refresh token using configured expiration.
     */
    String generateRefreshToken(Long userId, Roles role);

    /**
     * Verifies signature and expiration, returning {@link JwtPayload}.
     *
     * @throws io.jsonwebtoken.JwtException if the token is invalid
     */
    JwtPayload parse(String token);

    /**
     * Ensures the token type matches the expected one (e.g. refresh-only for token rotation).
     *
     * @throws IllegalArgumentException if the type does not match
     */
    void ensureType(JwtPayload payload, JwtTokenType expectedType);
}
