package com.javaintershipauthservice.security;

import com.javaintershipauthservice.model.Roles;

public record JwtPrincipal(Long userId, Roles role) {
}

