package com.example.auth.user;

import java.time.Clock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Loads users from the existing Oracle tables via MyBatis.
 * <p>
 * Password expiry is exposed through {@link SecurityUser#isCredentialsNonExpired()} rather than thrown
 * from here. {@code DaoAuthenticationProvider} then raises {@code CredentialsExpiredException} in its
 * post-authentication check, i.e. only <em>after</em> the password has been verified. Throwing it from
 * this method would run before the password check and let anyone who knows a user id learn that the
 * account's password has expired.
 */
@Service
public class DatabaseUserDetailsService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(DatabaseUserDetailsService.class);

    private final UserMapper userMapper;
    private final Clock clock;

    public DatabaseUserDetailsService(UserMapper userMapper, Clock clock) {
        this.userMapper = userMapper;
        this.clock = clock;
    }

    @Override
    @Transactional(readOnly = true)
    public SecurityUser loadUserByUsername(String userId) {
        if (userId == null || userId.isBlank()) {
            throw new UsernameNotFoundException("User id must not be blank");
        }

        SecurityUser user = userMapper.findByUserId(userId.trim())
                .map(account -> new SecurityUser(account, clock))
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!user.isCredentialsNonExpired()) {
            log.debug("Password for user '{}' expired at {}", user.getUsername(), user.getPasswordExpiresAt());
        }
        return user;
    }
}
