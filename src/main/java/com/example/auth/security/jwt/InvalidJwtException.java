package com.example.auth.security.jwt;

import org.springframework.security.core.AuthenticationException;

/** Raised when a bearer token cannot be trusted (bad signature, expired, malformed, wrong issuer). */
public class InvalidJwtException extends AuthenticationException {

    public InvalidJwtException(String message) {
        super(message);
    }

    public InvalidJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
