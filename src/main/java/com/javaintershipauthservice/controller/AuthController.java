package com.javaintershipauthservice.controller;

import com.javaintershipauthservice.dto.request.LoginRequest;
import com.javaintershipauthservice.dto.request.RefreshTokenRequest;
import com.javaintershipauthservice.dto.request.RegisterRequest;
import com.javaintershipauthservice.dto.response.TokenResponse;
import com.javaintershipauthservice.dto.request.ValidateTokenRequest;
import com.javaintershipauthservice.dto.response.ValidateTokenResponse;
import com.javaintershipauthservice.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/credentials")
    public Long register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @PostMapping("/validate")
    public ValidateTokenResponse validate(@Valid @RequestBody ValidateTokenRequest request) {
        return authService.validate(request);
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refresh(request);
    }

    @GetMapping("/csrf")
    public CsrfToken csrf(CsrfToken csrfToken) {
        return csrfToken;
    }
}

