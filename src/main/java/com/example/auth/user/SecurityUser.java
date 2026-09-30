package com.example.auth.user;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * {@link UserDetails} adapter over a {@link UserAccount} row.
 * <p>
 * Roles are normalised to Spring's {@code ROLE_} convention so they work with {@code hasRole("ADMIN")}
 * whether the database stores {@code ADMIN} or {@code ROLE_ADMIN}.
 */
public final class SecurityUser implements UserDetails {

    private static final String ROLE_PREFIX = "ROLE_";

    private final String userId;
    private final String passwordHash;
    private final LocalDateTime passwordExpiresAt;
    private final List<GrantedAuthority> authorities;
    private final Clock clock;

    public SecurityUser(UserAccount account, Clock clock) {
        this.userId = Objects.requireNonNull(account.getUserId(), "userId");
        this.passwordHash = account.getPasswordHash();
        this.passwordExpiresAt = account.getPasswordExpiresAt();
        this.clock = Objects.requireNonNull(clock, "clock");
        this.authorities = account.getRoles().stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(role -> !role.isEmpty())
                .map(role -> role.toUpperCase(Locale.ROOT))
                .map(role -> role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role)
                .distinct()
                .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                .toList();
    }

    @Override
    public String getUsername() {
        return userId;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     * A password is expired once the current time reaches the stored expiry timestamp.
     * A {@code NULL} expiry date in the database means the password never expires.
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return passwordExpiresAt == null || LocalDateTime.now(clock).isBefore(passwordExpiresAt);
    }

    public LocalDateTime getPasswordExpiresAt() {
        return passwordExpiresAt;
    }

    // Account-level flags: the existing schema has no columns for these. If it does (e.g. STATUS,
    // LOCKED_FLAG), select them in UserMapper.xml and evaluate them here.

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String toString() {
        return "SecurityUser[userId=" + userId + ", authorities=" + authorities + "]";
    }
}
