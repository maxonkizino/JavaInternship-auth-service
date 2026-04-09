package com.javaintershipauthservice.service;

import com.javaintershipauthservice.config.JwtProperties;
import com.javaintershipauthservice.model.Roles;
import com.javaintershipauthservice.security.JwtTokenType;
import com.javaintershipauthservice.service.impl.JwtServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(classes = JwtServiceTest.JwtServiceTestConfig.class)
@ActiveProfiles("test")
class JwtServiceTest {

    @Autowired
    private JwtService jwtService;

    @Test
    void generateAndParseAccessTokenSuccess() {
        String token = jwtService.generateAccessToken(42L, Roles.ROLE_ADMIN);
        JwtService.JwtPayload payload = jwtService.parse(token);

        assertEquals(42L, payload.userId());
        assertEquals(Roles.ROLE_ADMIN, payload.role());
        assertEquals(JwtTokenType.ACCESS, payload.type());
    }

    @Test
    void ensureTypeThrowsForUnexpectedTokenType() {
        String accessToken = jwtService.generateAccessToken(1L, Roles.ROLE_USER);
        JwtService.JwtPayload accessPayload = jwtService.parse(accessToken);

        assertThrows(IllegalArgumentException.class, () ->
                jwtService.ensureType(accessPayload, JwtTokenType.REFRESH)
        );
    }

    @Test
    void initThrowsWhenSecretIsTooShort() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("short-secret");

        JwtServiceImpl testJwtService = new JwtServiceImpl(properties);

        assertThrows(IllegalArgumentException.class, testJwtService::init);
    }

    @Configuration
    @EnableConfigurationProperties(JwtProperties.class)
    static class JwtServiceTestConfig {
        @Bean
        JwtService jwtService(JwtProperties jwtProperties) {
            JwtServiceImpl service = new JwtServiceImpl(jwtProperties);
            service.init();
            return service;
        }
    }
}

