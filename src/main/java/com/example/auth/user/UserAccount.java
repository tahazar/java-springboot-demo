package com.example.auth.user;

import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Row-level view of a user in the existing Oracle schema, populated by {@link UserMapper}.
 * A mutable JavaBean because MyBatis builds nested collections through setters.
 */
public class UserAccount {

    private String userId;
    private String passwordHash;
    /** {@code null} means the password never expires. */
    private LocalDateTime passwordExpiresAt;
    private Set<String> roles = new LinkedHashSet<>();

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public LocalDateTime getPasswordExpiresAt() {
        return passwordExpiresAt;
    }

    public void setPasswordExpiresAt(LocalDateTime passwordExpiresAt) {
        this.passwordExpiresAt = passwordExpiresAt;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    @Override
    public String toString() {
        // Never include the password hash in logs.
        return "UserAccount[userId=" + userId + ", passwordExpiresAt=" + passwordExpiresAt + ", roles=" + roles + "]";
    }
}
