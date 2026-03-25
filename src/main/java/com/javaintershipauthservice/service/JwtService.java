package com.javaintershipauthservice.service;

import com.javaintershipauthservice.model.Roles;
import com.javaintershipauthservice.config.JwtProperties;
import com.javaintershipauthservice.security.JwtTokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static final String CLAIM_ROLE = "role";
    private static final String CLAIM_TYPE = "type";

    private final JwtProperties properties;
    private byte[] secretBytes;
    private SecretKey signingKey;



    @PostConstruct
    void init() {
        if (properties.getSecret() == null || properties.getSecret().trim().isEmpty()) {
            throw new IllegalArgumentException("JWT secret is not configured (jwt.secret)");
        }
        secretBytes = properties.getSecret().getBytes(StandardCharsets.UTF_8);

        if (secretBytes.length < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 bytes for HS256");
        }

        signingKey = Keys.hmacShaKeyFor(secretBytes);
    }

    public String generateAccessToken(Long userId, Roles role) {
        return generateToken(userId, role, JwtTokenType.ACCESS, properties.getAccessTokenExpirationMinutes());
    }

    public String generateRefreshToken(Long userId, Roles role) {
        return generateToken(userId, role, JwtTokenType.REFRESH, properties.getRefreshTokenExpirationMinutes());
    }

    public JwtPayload parse(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        Long userId = Long.parseLong(claims.getSubject());
        Roles role = Roles.valueOf(claims.get(CLAIM_ROLE, String.class));
        JwtTokenType type = JwtTokenType.valueOf(claims.get(CLAIM_TYPE, String.class));

        Instant issuedAt = claims.getIssuedAt() != null ? claims.getIssuedAt().toInstant() : null;
        Instant expiresAt = claims.getExpiration() != null ? claims.getExpiration().toInstant() : null;

        return new JwtPayload(userId, role, type, issuedAt, expiresAt);
    }

    public void ensureType(JwtPayload payload, JwtTokenType expectedType) {
        if (payload.type() != expectedType) {
            throw new IllegalArgumentException("Invalid token type: expected " + expectedType);
        }
    }

    private String generateToken(Long userId, Roles role, JwtTokenType type, long expirationMinutes) {
        Instant now = Instant.now();
        Date issuedAt = Date.from(now);
        Date exp = Date.from(now.plusSeconds(expirationMinutes * 60));

        return Jwts.builder()
                .subject(userId.toString())
                .id(UUID.randomUUID().toString())
                .claim(CLAIM_ROLE, role.name())
                .claim(CLAIM_TYPE, type.name())
                .issuedAt(issuedAt)
                .expiration(exp)
                .signWith(signingKey)
                .compact();
    }

    public record JwtPayload(Long userId, Roles role, JwtTokenType type, Instant issuedAt, Instant expiresAt) {
    }

}

