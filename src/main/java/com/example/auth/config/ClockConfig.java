package com.example.auth.config;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Single source of "now" for token issuing and password-expiry checks, so both can be tested
 * deterministically.
 */
@Configuration(proxyBeanMethods = false)
public class ClockConfig {

    @Bean
    public Clock clock() {
        return Clock.systemDefaultZone();
    }
}
