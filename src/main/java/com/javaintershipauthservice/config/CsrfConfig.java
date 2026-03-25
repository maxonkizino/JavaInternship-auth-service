package com.javaintershipauthservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Set;

@Configuration
public class CsrfConfig {

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "TRACE", "OPTIONS");

    @Bean
    public CsrfTokenRepository csrfTokenRepository(Environment environment) {
        boolean httpOnly = environment.getProperty("security.csrf.cookie.http-only", Boolean.class, true);
        if (httpOnly) {
            return new CookieCsrfTokenRepository();
        }
        return CookieCsrfTokenRepository.withHttpOnlyFalse();
    }

    @Bean
    public RequestMatcher csrfProtectionMatcher() {
        return request -> {
            String method = request.getMethod();
            if (method != null && SAFE_METHODS.contains(method)) {
                return false;
            }

            String authorization = request.getHeader("Authorization");
            if (authorization != null && authorization.startsWith("Bearer ")) {
                return false;
            }

            String cookieHeader = request.getHeader("Cookie");
            return cookieHeader != null && !cookieHeader.isBlank();
        };
    }
}

