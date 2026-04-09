package com.javaintershipauthservice.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorsConfigTest {

    @Test
    void corsConfigurationSourceRegistersDefaults() {
        CorsConfig config = new CorsConfig();
        MockEnvironment env = new MockEnvironment()
                .withProperty("cors.allowed-origins", "http://localhost:8080");
        CorsConfigurationSource source = config.corsConfigurationSource(env);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/any");
        CorsConfiguration cors = source.getCorsConfiguration(request);

        assertNotNull(cors);
        assertTrue(cors.getAllowedOrigins().contains("http://localhost:8080"));
        assertTrue(cors.getAllowedMethods().contains("GET"));
        assertTrue(cors.getAllowedMethods().contains("POST"));
        assertTrue(cors.getAllowedHeaders().contains("Authorization"));
        assertTrue(cors.getAllowedHeaders().contains("Content-Type"));
        assertTrue(cors.getAllowedHeaders().contains("X-CSRF-TOKEN"));
        assertEquals(Boolean.TRUE, cors.getAllowCredentials());
    }
}

