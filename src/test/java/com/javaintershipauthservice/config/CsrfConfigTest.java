package com.javaintershipauthservice.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class CsrfConfigTest {

    @Test
    void csrfTokenRepositoryUsesHttpOnlyByDefault() {
        CsrfConfig config = new CsrfConfig();

        CsrfTokenRepository repo = config.csrfTokenRepository();

        assertInstanceOf(CookieCsrfTokenRepository.class, repo);
    }
}
