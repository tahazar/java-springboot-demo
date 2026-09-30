package com.example.auth.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank @Size(max = 100) String userId,
        // BCrypt ignores input beyond 72 bytes; the cap also bounds hashing cost for oversized payloads.
        @NotBlank @Size(max = 72) String password) {

    @Override
    public String toString() {
        return "LoginRequest[userId=" + userId + ", password=***]";
    }
}
