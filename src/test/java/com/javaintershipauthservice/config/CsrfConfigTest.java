package com.javaintershipauthservice.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CsrfConfigTest {

    @Test
    void csrfIgnoredRequestMatcherIgnoresAuthPaths() {
        CsrfConfig config = new CsrfConfig();
        RequestMatcher matcher = config.csrfIgnoredRequestMatcher();

        MockHttpServletRequest authRequest = new MockHttpServletRequest("POST", "/auth/login");
        MockHttpServletRequest otherRequest = new MockHttpServletRequest("POST", "/users/1");

        assertTrue(matcher.matches(authRequest));
        assertFalse(matcher.matches(otherRequest));
    }
}

