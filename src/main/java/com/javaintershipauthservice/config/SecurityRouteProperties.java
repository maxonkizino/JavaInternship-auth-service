package com.javaintershipauthservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.security.routes")
public class SecurityRouteProperties {

    private String users;

    private String usersId;

    private String usersStatus;

    private String paymentCards;
}
