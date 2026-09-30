package com.example.auth.user;

import java.util.Optional;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** SQL lives in {@code resources/mapper/UserMapper.xml}. */
@Mapper
public interface UserMapper {

    /**
     * Loads the user's credentials, password expiry date and roles in a single round-trip.
     *
     * @return empty if no user has this id
     */
    Optional<UserAccount> findByUserId(@Param("userId") String userId);
}
