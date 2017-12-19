package com.kumuluz.ee.jwt.auth.validator;

/**
 * Custom validation exception.
 *
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
public class JWTValidationException extends Exception {

    public JWTValidationException(String message) {
        super(message);
    }

    public JWTValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
