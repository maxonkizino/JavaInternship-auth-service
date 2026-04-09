package com.javaintershipauthservice.exception;

import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String KEY_ERROR = "error";
    private static final String KEY_MESSAGE = "message";
    private static final String KEY_FIELDS = "fields";

    private static final String ERROR_UNAUTHORIZED = "unauthorized";
    private static final String ERROR_BAD_REQUEST = "bad_request";
    private static final String ERROR_VALIDATION_FAILED = "validation_failed";
    private static final String ERROR_INTERNAL = "internal_error";

    @ExceptionHandler(BadCredentialsException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Map<String, Object> handleBadCredentials(BadCredentialsException e) {
        return Map.of(
                KEY_ERROR, ERROR_UNAUTHORIZED,
                KEY_MESSAGE, e.getMessage()
        );
    }

    @ExceptionHandler({IllegalArgumentException.class, JwtException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleBadRequest(RuntimeException e) {
        return Map.of(
                KEY_ERROR, ERROR_BAD_REQUEST,
                KEY_MESSAGE, e.getMessage()
        );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleValidation(MethodArgumentNotValidException e) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError fieldError : e.getBindingResult().getFieldErrors()) {
            errors.put(fieldError.getField(), fieldError.getDefaultMessage());
        }
        return Map.of(
                KEY_ERROR, ERROR_VALIDATION_FAILED,
                KEY_MESSAGE, "Request validation failed",
                KEY_FIELDS, errors
        );
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Map<String, Object> handleUnknown(Exception e) {
        return Map.of(
                KEY_ERROR, ERROR_INTERNAL,
                KEY_MESSAGE, e.getMessage()
        );
    }
}

