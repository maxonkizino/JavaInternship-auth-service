package com.javaintershipauthservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

@Configuration
public class CsrfConfig {

    @Bean
    public CsrfTokenRepository csrfTokenRepository(Environment environment) {
        boolean httpOnly = environment.getProperty("security.csrf.cookie.http-only", Boolean.class, true);
        if (httpOnly) {
            return new CookieCsrfTokenRepository();
        }
        return CookieCsrfTokenRepository.withHttpOnlyFalse();
    }
}

