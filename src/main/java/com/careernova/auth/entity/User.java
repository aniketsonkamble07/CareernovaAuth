package com.careernova.auth.entity;

import com.careernova.auth.enums.AuthProviderType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Data
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = "email"),
        @UniqueConstraint(columnNames = {"auth_provider_type", "provider_id"})
})
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String username;

    private String password;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_provider_type", nullable = false)
    private AuthProviderType authProviderType;

    @Column(name = "provider_id")
    private String providerId;

    private String profilePicture;

    @Column(name = "email_verified", nullable = false)
    @Builder.Default
    private Boolean emailVerified = false;

    @Column(name = "account_non_locked", nullable = false)
    @Builder.Default
    private Boolean accountNonLocked = true;

    @Column(name = "account_enabled", nullable = false)
    @Builder.Default
    private Boolean accountEnabled = true;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Transient
    private boolean newUser = false;

    // Helper methods for cleaner code
    public boolean isEnabled() {
        return accountEnabled != null ? accountEnabled : true;
    }

    public boolean isNonLocked() {
        return accountNonLocked != null ? accountNonLocked : true;
    }

    public boolean isEmailVerified() {
        return emailVerified != null ? emailVerified : false;
    }
}