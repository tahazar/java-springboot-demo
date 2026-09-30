package com.example.auth.config;

import com.example.auth.security.RestAccessDeniedHandler;
import com.example.auth.security.RestAuthenticationEntryPoint;
import com.example.auth.security.jwt.JwtAuthenticationFilter;
import com.example.auth.security.jwt.JwtService;

import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtService jwtService,
                                                   RestAuthenticationEntryPoint authenticationEntryPoint,
                                                   RestAccessDeniedHandler accessDeniedHandler) throws Exception {
        http
                // Stateless bearer-token API: no cookies-based session, so CSRF protection is not applicable.
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                // Must run before UsernamePasswordAuthenticationFilter so the SecurityContext is populated
                // by the time AuthorizationFilter evaluates the rules above.
                .addFilterBefore(new JwtAuthenticationFilter(jwtService, authenticationEntryPoint),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Used only by the login endpoint. {@link DaoAuthenticationProvider} performs, in order:
     * account-status checks, password verification (with timing-attack mitigation for unknown users),
     * then {@code isCredentialsNonExpired()} — throwing {@code CredentialsExpiredException} only after
     * the password has been proven correct.
     */
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);

        ProviderManager manager = new ProviderManager(provider);
        // Tokens carry the credentials only during authentication; never keep the raw password around.
        manager.setEraseCredentialsAfterAuthentication(true);
        return manager;
    }

    /**
     * Hashes stored with an id prefix (e.g. {@code {bcrypt}$2a$...}) are verified by the matching encoder;
     * legacy hashes without a prefix are assumed to be plain BCrypt. Adjust the fallback if the existing
     * Oracle table stores a different algorithm.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        String idForEncode = "bcrypt";
        BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
        DelegatingPasswordEncoder encoder = new DelegatingPasswordEncoder(idForEncode, Map.of(idForEncode, bcrypt));
        encoder.setDefaultPasswordEncoderForMatches(bcrypt);
        return encoder;
    }
}
