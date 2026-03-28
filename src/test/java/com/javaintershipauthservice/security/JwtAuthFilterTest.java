package com.javaintershipauthservice.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.javaintershipauthservice.exception.RestAuthenticationEntryPoint;
import com.javaintershipauthservice.service.JwtService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    @Mock
    private JwtService jwtService;

    private final RestAuthenticationEntryPoint authenticationEntryPoint = new RestAuthenticationEntryPoint(new ObjectMapper());

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void whenNoAuthorizationHeader_thenPassThroughWithoutAuthentication() throws Exception {
        JwtAuthFilter filter = new JwtAuthFilter(jwtService, authenticationEntryPoint);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = org.mockito.Mockito.mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNull(authentication);
        verify(chain).doFilter(request, response);
    }

    @Test
    void whenValidAccessToken_thenSetsAuthenticationAndCallsChain() throws Exception {
        JwtAuthFilter filter = new JwtAuthFilter(jwtService, authenticationEntryPoint);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer token");
        request.setRemoteAddr("127.0.0.1");

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = org.mockito.Mockito.mock(FilterChain.class);

        JwtService.JwtPayload payload = new JwtService.JwtPayload(
                42L,
                com.javaintershipauthservice.model.Roles.ROLE_USER,
                JwtTokenType.ACCESS,
                Instant.now(),
                Instant.now().plusSeconds(60)
        );

        when(jwtService.parse("token")).thenReturn(payload);
        doNothing().when(jwtService).ensureType(payload, JwtTokenType.ACCESS);

        filter.doFilter(request, response, chain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertEquals(payload.userId(), ((JwtPrincipal) authentication.getPrincipal()).userId());
        assertEquals(payload.role(), ((JwtPrincipal) authentication.getPrincipal()).role());

        assertEquals(
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                List.copyOf(authentication.getAuthorities())
        );
        verify(chain).doFilter(request, response);
    }

    @Test
    void whenJwtIsInvalid_thenClearsContextAndReturns401() throws Exception {
        JwtAuthFilter filter = new JwtAuthFilter(jwtService, authenticationEntryPoint);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer bad");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = org.mockito.Mockito.mock(FilterChain.class);

        when(jwtService.parse("bad")).thenThrow(new JwtException("bad"));

        filter.doFilter(request, response, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
        verify(chain, never()).doFilter(request, response);
    }
}
