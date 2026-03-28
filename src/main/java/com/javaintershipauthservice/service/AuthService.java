package com.javaintershipauthservice.service;

import com.javaintershipauthservice.dto.request.LoginRequest;
import com.javaintershipauthservice.dto.request.RegisterRequest;
import com.javaintershipauthservice.dto.request.RefreshTokenRequest;
import com.javaintershipauthservice.dto.response.TokenResponse;
import com.javaintershipauthservice.dto.request.ValidateTokenRequest;
import com.javaintershipauthservice.dto.response.ValidateTokenResponse;
import com.javaintershipauthservice.model.Role;
import com.javaintershipauthservice.model.Roles;
import com.javaintershipauthservice.model.User;
import com.javaintershipauthservice.repository.RoleRepository;
import com.javaintershipauthservice.repository.UserRepository;
import com.javaintershipauthservice.security.JwtTokenType;
import io.jsonwebtoken.JwtException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;



    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByLogin(request.login())
                .orElseThrow(() -> new BadCredentialsException("Invalid login or password"));

        if (Boolean.FALSE.equals(user.getActive())) {
            throw new BadCredentialsException("User is not active");
        }

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BadCredentialsException("Invalid login or password");
        }

        Roles role = resolveRole(user.getId());

        String accessToken = jwtService.generateAccessToken(user.getUserId(), role);
        String refreshToken = jwtService.generateRefreshToken(user.getUserId(), role);
        return new TokenResponse(accessToken, refreshToken);
    }

    public Long register(RegisterRequest request) {
        if (userRepository.existsByUserId(request.userId())) {
            throw new IllegalArgumentException("UserId already exists");
        }
        if (userRepository.existsByLogin(request.login())) {
            throw new IllegalArgumentException("Login already exists");
        }

        User user = new User();
        user.setUserId(request.userId());
        user.setLogin(request.login());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setEmail(request.email());
        user.setActive(true);

        User saved = userRepository.save(user);

        Role userRole = new Role();
        userRole.setUser(saved);
        userRole.setRoleValue(Roles.ROLE_USER);
        roleRepository.save(userRole);

        return saved.getUserId();
    }

    public ValidateTokenResponse validate(ValidateTokenRequest request) {
        try {
            JwtService.JwtPayload payload = jwtService.parse(request.token());
            Instant expiresAt = payload.expiresAt();
            return new ValidateTokenResponse(
                    true,
                    payload.userId(),
                    payload.role(),
                    payload.type().name(),
                    expiresAt
            );
        } catch (JwtException | IllegalArgumentException e) {
            return new ValidateTokenResponse(false, null, null, null, null);
        }
    }

    public TokenResponse refresh(RefreshTokenRequest request) {
        JwtService.JwtPayload payload = jwtService.parse(request.refreshToken());
        jwtService.ensureType(payload, JwtTokenType.REFRESH);

        User user = userRepository.findByUserId(payload.userId())
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));
        if (Boolean.FALSE.equals(user.getActive())) {
            throw new BadCredentialsException("User is not active");
        }

        String accessToken = jwtService.generateAccessToken(payload.userId(), payload.role());
        String refreshToken = jwtService.generateRefreshToken(payload.userId(), payload.role());
        return new TokenResponse(accessToken, refreshToken);
    }

    private Roles resolveRole(Long userId) {
        List<Role> roles = roleRepository.findByUser_Id(userId);
        if (roles == null || roles.isEmpty()) {
            return Roles.ROLE_USER;
        }
        return roles.get(0).getRoleValue();
    }
}

