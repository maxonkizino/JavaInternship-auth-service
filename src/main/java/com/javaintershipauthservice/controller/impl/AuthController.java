package com.javaintershipauthservice.controller.impl;

import com.javaintershipauthservice.controller.AuthApi;
import com.javaintershipauthservice.dto.request.LoginRequest;
import com.javaintershipauthservice.dto.request.RefreshTokenRequest;
import com.javaintershipauthservice.dto.request.RegisterRequest;
import com.javaintershipauthservice.dto.response.TokenResponse;
import com.javaintershipauthservice.dto.request.ValidateTokenRequest;
import com.javaintershipauthservice.dto.response.ValidateTokenResponse;
import com.javaintershipauthservice.logging.ControllerLogger;
import com.javaintershipauthservice.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

/**
 * HTTP adapter for {@link AuthApi}; delegates to {@link AuthService}.
 */
@RestController
@RequiredArgsConstructor
public class AuthController implements AuthApi {

    private final AuthService authService;
    private final ControllerLogger controllerLogger;

    @Override
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        controllerLogger.methodCalled("AuthController", "login", request.login());
        return authService.login(request);
    }

    @Override
    public Long register(@Valid @RequestBody RegisterRequest request) {
        controllerLogger.methodCalled("AuthController", "register", request.login(), request.email());
        return authService.register(request);
    }

    @Override
    public ValidateTokenResponse validate(@Valid @RequestBody ValidateTokenRequest request) {
        controllerLogger.methodCalled("AuthController", "validate");
        return authService.validate(request);
    }

    @Override
    public TokenResponse refresh(@Valid @RequestBody RefreshTokenRequest request) {
        controllerLogger.methodCalled("AuthController", "refresh");
        return authService.refresh(request);
    }

    @Override
    public CsrfToken csrf(CsrfToken csrfToken) {
        controllerLogger.methodCalled("AuthController", "csrf");
        return csrfToken;
    }
}
