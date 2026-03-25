package com.javaintershipauthservice.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.javaintershipauthservice.security.JwtAuthFilter;
import com.javaintershipauthservice.exception.RestAccessDeniedHandler;
import com.javaintershipauthservice.exception.RestAuthenticationEntryPoint;
import com.javaintershipauthservice.service.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityConfig {

    private static final String ROLE_USER = "ROLE_USER";
    private static final String ROLE_ADMIN = "ROLE_ADMIN";

    private static final String USERS_ID = "/users/*";
    private static final String PAYMENT_CARDS = "/payment-cards";
    private static final String PAYMENT_CARDS_ID = "/payment-cards/*";
    private static final String PAYMENT_CARDS_ID_STATUS = "/payment-cards/*/status";
    private static final String PAYMENT_CARDS_BY_USER = "/payment-cards/by-user/*";
    private static final String PAYMENT_CARDS_BY_NUMBER = "/payment-cards/by-number/*";

    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public RestAuthenticationEntryPoint authenticationEntryPoint() {
        return new RestAuthenticationEntryPoint(new ObjectMapper());
    }

    @Bean
    public RestAccessDeniedHandler accessDeniedHandler() {
        return new RestAccessDeniedHandler(new ObjectMapper());
    }

    @Bean
    public JwtAuthFilter jwtAuthFilter(JwtService jwtService) {
        return new JwtAuthFilter(jwtService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthFilter jwtAuthFilter,
            RestAuthenticationEntryPoint entryPoint,
            RestAccessDeniedHandler accessDeniedHandler,
            CsrfTokenRepository csrfTokenRepository,
            RequestMatcher csrfProtectionMatcher
    ) {

        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository)
                        .requireCsrfProtectionMatcher(csrfProtectionMatcher)
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        
                        .requestMatchers(HttpMethod.GET, USERS_ID).hasAnyAuthority(ROLE_USER)
                        .requestMatchers(HttpMethod.PUT, USERS_ID).hasAnyAuthority(ROLE_USER)

                        .requestMatchers(HttpMethod.GET, PAYMENT_CARDS_BY_USER).hasAnyAuthority(ROLE_USER)
                        .requestMatchers(HttpMethod.GET, PAYMENT_CARDS_BY_NUMBER).hasAnyAuthority(ROLE_USER)
                        .requestMatchers(HttpMethod.GET, PAYMENT_CARDS_ID).hasAnyAuthority(ROLE_USER)

                        .requestMatchers(HttpMethod.POST, PAYMENT_CARDS).hasAnyAuthority(ROLE_USER)
                        .requestMatchers(HttpMethod.PUT, PAYMENT_CARDS_ID).hasAnyAuthority(ROLE_USER)
                        .requestMatchers(HttpMethod.DELETE, PAYMENT_CARDS_ID).hasAnyAuthority(ROLE_USER)
                        .requestMatchers(HttpMethod.PATCH, PAYMENT_CARDS_ID_STATUS).hasAnyAuthority(ROLE_USER)

                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/users/**").hasAuthority(ROLE_ADMIN)
                        .requestMatchers("/payment-cards/**").hasAuthority(ROLE_ADMIN)

                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

