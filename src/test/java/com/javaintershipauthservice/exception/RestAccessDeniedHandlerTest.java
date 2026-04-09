package com.javaintershipauthservice.exception;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RestAccessDeniedHandlerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void handleWritesForbiddenJson() throws Exception {
        RestAccessDeniedHandler handler = new RestAccessDeniedHandler(objectMapper);
        HttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        AccessDeniedException ex = new AccessDeniedException("forbidden");

        handler.handle(request, response, ex);

        assertEquals(403, response.getStatus());
        assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());

        Map<String, Object> body = objectMapper.readValue(
                response.getContentAsString(),
                new TypeReference<Map<String, Object>>() {
                }
        );
        assertNotNull(body.get("error"));
        assertEquals("forbidden", body.get("error"));
        assertEquals("forbidden", body.get("message"));
    }
}

