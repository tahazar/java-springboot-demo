package com.example.auth.web;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Example protected endpoints demonstrating URL-based and method-based RBAC. */
@RestController
@RequestMapping("/api")
public class ProfileController {

    /** Any authenticated user. */
    @GetMapping("/me")
    public CurrentUser me(Authentication authentication) {
        return new CurrentUser(authentication.getName(),
                authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }

    /** Protected by the {@code /api/admin/**} rule in {@code SecurityConfig}. */
    @GetMapping("/admin/ping")
    public String adminPing() {
        return "pong";
    }

    public record CurrentUser(String userId, List<String> roles) {
    }
}
