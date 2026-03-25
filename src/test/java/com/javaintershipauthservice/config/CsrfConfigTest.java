package com.javaintershipauthservice.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class CsrfConfigTest {

    @Test
    void csrfTokenRepositoryUsesHttpOnlyByDefault() {
        CsrfConfig config = new CsrfConfig();
        MockEnvironment env = new MockEnvironment();
        CsrfTokenRepository repo = config.csrfTokenRepository(env);
        assertInstanceOf(CookieCsrfTokenRepository.class, repo);
    }

    @Test
    void csrfTokenRepositoryCanDisableHttpOnlyForDev() {
        CsrfConfig config = new CsrfConfig();
        MockEnvironment env = new MockEnvironment()
                .withProperty("security.csrf.cookie.http-only", "false");
        CsrfTokenRepository repo = config.csrfTokenRepository(env);
        assertInstanceOf(CookieCsrfTokenRepository.class, repo);
        assertTrue(repo instanceof CookieCsrfTokenRepository);
    }
}

