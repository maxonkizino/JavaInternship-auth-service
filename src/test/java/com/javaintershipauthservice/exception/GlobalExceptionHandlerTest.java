package com.javaintershipauthservice.exception;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.core.MethodParameter;

import java.lang.reflect.Constructor;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GlobalExceptionHandlerTest {

    @Test
    void handleBadCredentialsReturnsUnauthorized() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        BadCredentialsException ex = new BadCredentialsException("invalid login");

        Map<String, Object> body = handler.handleBadCredentials(ex);

        assertEquals("unauthorized", body.get("error"));
        assertEquals("invalid login", body.get("message"));
    }

    @Test
    void handleBadRequestCatchesIllegalArgumentException() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        IllegalArgumentException ex = new IllegalArgumentException("bad payload");

        Map<String, Object> body = handler.handleBadRequest(ex);

        assertEquals("bad_request", body.get("error"));
        assertEquals("bad payload", body.get("message"));
    }

    @Test
    void handleUnknownReturnsInternalError() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        RuntimeException ex = new RuntimeException("boom");

        Map<String, Object> body = handler.handleUnknown(ex);

        assertEquals("internal_error", body.get("error"));
        assertEquals("boom", body.get("message"));
    }

    @Test
    void handleValidationReturnsFieldErrors() throws Exception {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();

        // Build MethodArgumentNotValidException instance via reflection to avoid coupling
        // to Spring's constructor signature.
        class Dummy {
            @SuppressWarnings("unused")
            public void dummy(String s) {
            }
        }

        MethodParameter methodParameter = new MethodParameter(Dummy.class.getMethod("dummy", String.class), 0);
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Dummy(), "dummy");
        bindingResult.addError(new FieldError("dummy", "login", "login must not be blank"));

        MethodArgumentNotValidException ex = buildMethodArgumentNotValidException(methodParameter, bindingResult);

        Map<String, Object> body = handler.handleValidation(ex);

        assertEquals("validation_failed", body.get("error"));
        assertEquals("Request validation failed", body.get("message"));
        assertNotNull(body.get("fields"));
        @SuppressWarnings("unchecked")
        Map<String, String> fields = (Map<String, String>) body.get("fields");
        assertTrue(fields.containsKey("login"));
    }

    private MethodArgumentNotValidException buildMethodArgumentNotValidException(
            MethodParameter methodParameter,
            BeanPropertyBindingResult bindingResult
    ) throws Exception {
        Constructor<?>[] ctors = MethodArgumentNotValidException.class.getDeclaredConstructors();
        for (Constructor<?> ctor : ctors) {
            ctor.setAccessible(true);
            Class<?>[] paramTypes = ctor.getParameterTypes();
            Object[] args = new Object[paramTypes.length];

            for (int i = 0; i < paramTypes.length; i++) {
                Class<?> pt = paramTypes[i];
                if (MethodParameter.class.isAssignableFrom(pt)) {
                    args[i] = methodParameter;
                } else if (org.springframework.validation.BindingResult.class.isAssignableFrom(pt)) {
                    args[i] = bindingResult;
                } else if (String.class.equals(pt)) {
                    args[i] = "bad_request";
                } else {
                    args[i] = null;
                }
            }

            try {
                Object instance = ctor.newInstance(args);
                if (instance instanceof MethodArgumentNotValidException manve) {
                    return manve;
                }
            } catch (Exception ignored) {
                // try next constructor
            }
        }

        throw new IllegalStateException("Could not create MethodArgumentNotValidException with available constructors");
    }
}

