package com.careernova.auth.repository;

import com.careernova.auth.entity.User;
import com.careernova.auth.enums.AuthProviderType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);

    Optional<User> findByAuthProviderTypeAndProviderId(
            AuthProviderType authProviderType,
            String providerId
    );
}
