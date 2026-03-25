package com.javaintershipauthservice.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CsrfConfigTest {

    @Test
    void csrfProtectionMatcherDoesNotRequireTokenForBearerRequests() {
        CsrfConfig config = new CsrfConfig();
        RequestMatcher matcher = config.csrfProtectionMatcher();

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/users/1");
        request.addHeader("Authorization", "Bearer token");
        request.addHeader("Cookie", "XSRF-TOKEN=abc");

        assertFalse(matcher.matches(request));
    }

    @Test
    void csrfProtectionMatcherRequiresTokenForCookieBasedUnsafeRequests() {
        CsrfConfig config = new CsrfConfig();
        RequestMatcher matcher = config.csrfProtectionMatcher();

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/users/1");
        request.addHeader("Cookie", "SESSION=abc");

        assertTrue(matcher.matches(request));
    }

    @Test
    void csrfProtectionMatcherDoesNotRequireTokenForSafeMethods() {
        CsrfConfig config = new CsrfConfig();
        RequestMatcher matcher = config.csrfProtectionMatcher();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/users/1");
        request.addHeader("Cookie", "SESSION=abc");

        assertFalse(matcher.matches(request));
    }
}

