package com.javaintershipauthservice.service;

import com.javaintershipauthservice.PostgresIntegrationTestBase;
import com.javaintershipauthservice.dto.request.LoginRequest;
import com.javaintershipauthservice.dto.request.RefreshTokenRequest;
import com.javaintershipauthservice.dto.request.RegisterRequest;
import com.javaintershipauthservice.dto.request.ValidateTokenRequest;
import com.javaintershipauthservice.dto.response.TokenResponse;
import com.javaintershipauthservice.dto.response.ValidateTokenResponse;
import com.javaintershipauthservice.model.Roles;
import com.javaintershipauthservice.repository.RoleRepository;
import com.javaintershipauthservice.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("test")
class AuthServiceIntegrationTest extends PostgresIntegrationTestBase {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @BeforeEach
    void cleanDb() {
        roleRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void registerLoginValidateRefreshFlowWorks() {
        RegisterRequest registerRequest = new RegisterRequest(
                1001L,
                "integration_user",
                "secret",
                "integration@test.com",
                Roles.ROLE_USER
        );

        Long createdUserId = authService.register(registerRequest);
        assertEquals(1001L, createdUserId);

        TokenResponse loginTokens = authService.login(new LoginRequest("integration_user", "secret"));
        assertNotNull(loginTokens.accessToken());
        assertNotNull(loginTokens.refreshToken());

        ValidateTokenResponse validate = authService.validate(new ValidateTokenRequest(loginTokens.accessToken()));
        assertTrue(validate.valid());
        assertEquals(1001L, validate.userId());
        assertEquals(Roles.ROLE_USER, validate.role());
        assertEquals("ACCESS", validate.type());
        assertNotNull(validate.expiresAt());

        TokenResponse refreshed = authService.refresh(new RefreshTokenRequest(loginTokens.refreshToken()));
        assertNotNull(refreshed.accessToken());
        assertNotNull(refreshed.refreshToken());
    }

    @Test
    void validateReturnsFalseForInvalidToken() {
        ValidateTokenResponse validate = authService.validate(new ValidateTokenRequest("not-a-jwt"));
        assertFalse(validate.valid());
    }
}

