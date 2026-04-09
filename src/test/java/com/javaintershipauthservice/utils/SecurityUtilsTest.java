package com.javaintershipauthservice.utils;

import com.javaintershipauthservice.model.Roles;
import com.javaintershipauthservice.security.JwtPrincipal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SecurityUtilsTest {

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void getCurrentUserIdReturnsNullWhenNoAuthentication() {
        assertNull(SecurityUtils.getCurrentUserId());
    }

    @Test
    void getCurrentUserIdReturnsNullWhenPrincipalIsNotJwtPrincipal() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("user", null)
        );
        assertNull(SecurityUtils.getCurrentUserId());
    }

    @Test
    void getCurrentUserIdReturnsIdFromJwtPrincipal() {
        JwtPrincipal principal = new JwtPrincipal(123L, Roles.ROLE_USER);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, null)
        );
        assertEquals(123L, SecurityUtils.getCurrentUserId());
    }
}

