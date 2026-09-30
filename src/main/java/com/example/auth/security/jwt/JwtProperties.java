package com.example.auth.security.jwt;

import java.time.Duration;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * JWT settings bound from {@code app.security.jwt.*}.
 *
 * @param secret         Base64-encoded HMAC key; must decode to at least 256 bits (32 bytes) for HS256
 * @param issuer         value written to and required in the {@code iss} claim
 * @param accessTokenTtl lifetime of an access token; keep it short (e.g. 15m)
 * @param clockSkew      tolerance applied when validating {@code exp}/{@code nbf}
 */
@Validated
@ConfigurationProperties(prefix = "app.security.jwt")
public record JwtProperties(
        @NotBlank String secret,
        @NotBlank String issuer,
        @NotNull Duration accessTokenTtl,
        @NotNull Duration clockSkew) {
}
