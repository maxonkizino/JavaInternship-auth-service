package com.javaintershipauthservice.service;

import com.javaintershipauthservice.dto.request.LoginRequest;
import com.javaintershipauthservice.dto.request.RefreshTokenRequest;
import com.javaintershipauthservice.dto.request.RegisterRequest;
import com.javaintershipauthservice.dto.request.ValidateTokenRequest;
import com.javaintershipauthservice.dto.response.TokenResponse;
import com.javaintershipauthservice.dto.response.ValidateTokenResponse;
import com.javaintershipauthservice.model.Role;
import com.javaintershipauthservice.model.Roles;
import com.javaintershipauthservice.model.User;
import com.javaintershipauthservice.repository.RoleRepository;
import com.javaintershipauthservice.repository.UserRepository;
import com.javaintershipauthservice.security.JwtTokenType;
import com.javaintershipauthservice.service.impl.AuthServiceImpl;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthServiceImpl authService;

    @Test
    void loginSuccessReturnsTokensWithExternalUserId() {
        User user = new User();
        user.setId(1L);
        user.setUserId(101L);
        user.setLogin("max");
        user.setPassword("hashed");
        user.setActive(true);

        Role role = new Role();
        role.setRoleValue(Roles.ROLE_ADMIN);

        when(userRepository.findByLogin("max")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "hashed")).thenReturn(true);
        when(roleRepository.findByUser_Id(1L)).thenReturn(List.of(role));
        when(jwtService.generateAccessToken(101L, Roles.ROLE_ADMIN)).thenReturn("access");
        when(jwtService.generateRefreshToken(101L, Roles.ROLE_ADMIN)).thenReturn("refresh");

        TokenResponse response = authService.login(new LoginRequest("max", "secret"));

        assertEquals("access", response.accessToken());
        assertEquals("refresh", response.refreshToken());
        verify(jwtService).generateAccessToken(101L, Roles.ROLE_ADMIN);
        verify(jwtService).generateRefreshToken(101L, Roles.ROLE_ADMIN);
    }

    @Test
    void registerSuccessStoresEncodedPasswordAndDefaultRole() {
        RegisterRequest request = new RegisterRequest(777L, "new_user", "raw", "u@test.com");

        when(userRepository.existsByUserId(777L)).thenReturn(false);
        when(userRepository.existsByLogin("new_user")).thenReturn(false);
        when(passwordEncoder.encode("raw")).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User u = invocation.getArgument(0);
            u.setId(10L);
            return u;
        });

        Long createdUserId = authService.register(request);

        assertEquals(777L, createdUserId);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertEquals(777L, savedUser.getUserId());
        assertEquals("new_user", savedUser.getLogin());
        assertEquals("hashed", savedUser.getPassword());
        assertTrue(savedUser.getActive());

        ArgumentCaptor<Role> roleCaptor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository).save(roleCaptor.capture());
        assertEquals(Roles.ROLE_USER, roleCaptor.getValue().getRoleValue());
        assertNotNull(roleCaptor.getValue().getUser());
    }

    @Test
    void loginThrowsWhenPasswordInvalid() {
        User user = new User();
        user.setId(1L);
        user.setLogin("max");
        user.setPassword("hashed");
        user.setActive(true);

        when(userRepository.findByLogin("max")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("bad", "hashed")).thenReturn(false);

        LoginRequest badRequest = new LoginRequest("max", "bad");
        assertThrows(BadCredentialsException.class, () -> authService.login(badRequest));
    }

    @Test
    void validateReturnsFalseWhenTokenIsInvalid() {
        when(jwtService.parse("bad-token")).thenThrow(new JwtException("bad"));

        ValidateTokenResponse response = authService.validate(new ValidateTokenRequest("bad-token"));

        assertFalse(response.valid());
    }

    @Test
    void refreshReturnsNewPairWhenRefreshTokenIsValid() {
        JwtService.JwtPayload payload = new JwtService.JwtPayload(
                555L, Roles.ROLE_USER, JwtTokenType.REFRESH, Instant.now(), Instant.now().plusSeconds(60)
        );
        User user = new User();
        user.setUserId(555L);
        user.setActive(true);

        when(jwtService.parse("refresh-token")).thenReturn(payload);
        when(userRepository.findByUserId(555L)).thenReturn(Optional.of(user));
        when(jwtService.generateAccessToken(555L, Roles.ROLE_USER)).thenReturn("new-access");
        when(jwtService.generateRefreshToken(555L, Roles.ROLE_USER)).thenReturn("new-refresh");

        TokenResponse response = authService.refresh(new RefreshTokenRequest("refresh-token"));

        assertEquals("new-access", response.accessToken());
        assertEquals("new-refresh", response.refreshToken());
        verify(jwtService).ensureType(payload, JwtTokenType.REFRESH);
    }

    @Test
    void refreshThrowsWhenUserInactive() {
        JwtService.JwtPayload payload = new JwtService.JwtPayload(
                555L, Roles.ROLE_USER, JwtTokenType.REFRESH, Instant.now(), Instant.now().plusSeconds(60)
        );
        User user = new User();
        user.setUserId(555L);
        user.setActive(false);

        when(jwtService.parse("refresh-token")).thenReturn(payload);
        when(userRepository.findByUserId(555L)).thenReturn(Optional.of(user));

        assertThrows(BadCredentialsException.class,
                () -> authService.refresh(new RefreshTokenRequest("refresh-token")));
    }
}

