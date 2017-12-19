package com.kumuluz.ee.jwt.auth.validator;

public class JWTValidationException extends Exception {

    public JWTValidationException(String message) {
        super(message);
    }

    public JWTValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
