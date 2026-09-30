package com.example.auth.security.jwt;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates requests carrying {@code Authorization: Bearer <jwt>}.
 * <p>
 * Requests without a bearer token pass through untouched (the authorization rules decide whether
 * anonymous access is allowed). A bearer token that is present but invalid is rejected immediately
 * with 401 rather than silently downgraded to anonymous.
 * <p>
 * Authentication is built purely from the token's claims, so there is no database round-trip per
 * request; the short token lifetime bounds how long a role change or password expiry takes to apply.
 * <p>
 * Deliberately not a Spring bean: Spring Boot auto-registers every {@code Filter} bean in the servlet
 * container, which would run this filter twice. It is instantiated inside the security configuration.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final SecurityContextHolderStrategy securityContextHolderStrategy =
            SecurityContextHolder.getContextHolderStrategy();
    private final WebAuthenticationDetailsSource authenticationDetailsSource = new WebAuthenticationDetailsSource();

    public JwtAuthenticationFilter(JwtService jwtService, AuthenticationEntryPoint authenticationEntryPoint) {
        this.jwtService = jwtService;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            chain.doFilter(request, response);
            return;
        }

        String token = header.substring(BEARER_PREFIX.length()).trim();
        try {
            JwtService.AccessTokenClaims claims = jwtService.parseAndValidate(token);

            List<GrantedAuthority> authorities = claims.roles().stream()
                    .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                    .toList();
            UsernamePasswordAuthenticationToken authentication =
                    UsernamePasswordAuthenticationToken.authenticated(claims.userId(), null, authorities);
            authentication.setDetails(authenticationDetailsSource.buildDetails(request));

            SecurityContext context = securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authentication);
            securityContextHolderStrategy.setContext(context);
        } catch (InvalidJwtException ex) {
            securityContextHolderStrategy.clearContext();
            authenticationEntryPoint.commence(request, response, ex);
            return;
        }

        chain.doFilter(request, response);
    }
}
