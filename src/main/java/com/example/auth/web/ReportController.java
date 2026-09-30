package com.example.auth.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Example of method-level RBAC via {@code @EnableMethodSecurity}. */
@RestController
@RequestMapping("/api/reports")
public class ReportController {

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public String reports() {
        return "reports";
    }
}
