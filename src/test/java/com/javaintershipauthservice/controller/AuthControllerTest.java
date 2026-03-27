package com.javaintershipauthservice.controller;

import com.javaintershipauthservice.dto.request.LoginRequest;
import com.javaintershipauthservice.dto.request.RefreshTokenRequest;
import com.javaintershipauthservice.dto.request.RegisterRequest;
import com.javaintershipauthservice.dto.request.ValidateTokenRequest;
import com.javaintershipauthservice.dto.response.TokenResponse;
import com.javaintershipauthservice.dto.response.ValidateTokenResponse;
import com.javaintershipauthservice.service.AuthService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.CsrfToken;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;

    @InjectMocks
    private AuthController controller;

    @Test
    void loginDelegatesToAuthService() {
        LoginRequest request = new LoginRequest("login", "password");
        TokenResponse expected = new TokenResponse("access", "refresh");

        when(authService.login(request)).thenReturn(expected);

        TokenResponse actual = controller.login(request);
        assertEquals(expected, actual);
        verify(authService).login(request);
    }

    @Test
    void registerDelegatesToAuthService() {
        RegisterRequest request = new RegisterRequest(777L, "login", "password", "u@test.com");
        Long expectedUserId = 777L;

        when(authService.register(request)).thenReturn(expectedUserId);

        Long actualUserId = controller.register(request);
        assertEquals(expectedUserId, actualUserId);
        verify(authService).register(request);
    }

    @Test
    void validateDelegatesToAuthService() {
        ValidateTokenRequest request = new ValidateTokenRequest("token");
        ValidateTokenResponse expected = new ValidateTokenResponse(true, 1L, null, "ACCESS", null);

        when(authService.validate(request)).thenReturn(expected);

        ValidateTokenResponse actual = controller.validate(request);
        assertEquals(expected, actual);
        verify(authService).validate(request);
    }

    @Test
    void refreshDelegatesToAuthService() {
        RefreshTokenRequest request = new RefreshTokenRequest("refresh");
        TokenResponse expected = new TokenResponse("newAccess", "newRefresh");

        when(authService.refresh(request)).thenReturn(expected);

        TokenResponse actual = controller.refresh(request);
        assertEquals(expected, actual);
        verify(authService).refresh(request);
    }

    @Test
    void csrfReturnsProvidedToken() {
        CsrfToken token = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "value");
        assertEquals(token, controller.csrf(token));
    }
}

