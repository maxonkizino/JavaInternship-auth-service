package com.javaintershipauthservice.service;

import com.javaintershipauthservice.model.Roles;
import com.javaintershipauthservice.config.JwtProperties;
import com.javaintershipauthservice.security.JwtTokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

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



    @PostConstruct
    void init() {
        if (properties.getSecret() == null || properties.getSecret().trim().isEmpty()) {
            throw new IllegalArgumentException("JWT secret is not configured (jwt.secret)");
        }
        secretBytes = properties.getSecret().getBytes(StandardCharsets.UTF_8);

        if (secretBytes.length < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 bytes for HS256");
        }
    }

    public String generateAccessToken(Long userId, Roles role) {
        return generateToken(userId, role, JwtTokenType.ACCESS, properties.getAccessTokenExpirationMinutes());
    }

    public String generateRefreshToken(Long userId, Roles role) {
        return generateToken(userId, role, JwtTokenType.REFRESH, properties.getRefreshTokenExpirationMinutes());
    }

    public JwtPayload parse(String token) {
        Jws<Claims> jws = Jwts.parser()
                .setSigningKey(Keys.hmacShaKeyFor(secretBytes))
                .build()
                .parseClaimsJws(token);

        Claims claims = jws.getBody();
        String subject = claims.getSubject();

        Roles role = Roles.valueOf((String) claims.get(CLAIM_ROLE));
        JwtTokenType type = JwtTokenType.valueOf((String) claims.get(CLAIM_TYPE));

        Instant issuedAt = claims.getIssuedAt() != null ? claims.getIssuedAt().toInstant() : null;
        Instant expiresAt = claims.getExpiration() != null ? claims.getExpiration().toInstant() : null;

        return new JwtPayload(Long.parseLong(subject), role, type, issuedAt, expiresAt);
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
                .setSubject(userId.toString())
                .setId(UUID.randomUUID().toString())
                .claim(CLAIM_ROLE, role.name())
                .claim(CLAIM_TYPE, type.name())
                .setIssuedAt(issuedAt)
                .setExpiration(exp)
                .signWith(Keys.hmacShaKeyFor(secretBytes), SignatureAlgorithm.HS256)
                .compact();
    }

    public record JwtPayload(Long userId, Roles role, JwtTokenType type, Instant issuedAt, Instant expiresAt) {
    }

}

