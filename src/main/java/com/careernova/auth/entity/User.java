package com.careernova.auth.entity;

import com.careernova.auth.enums.AuthProviderType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
        name = "users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"authProviderType", "providerId"}),
                @UniqueConstraint(columnNames = {"email"})
        }
)
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // For normal login or display name
    private String username;

    // Nullable for OAuth users
    private String password;

    @Column(nullable = false)
    private String email;

    // OAuth provider user id
    private String providerId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuthProviderType authProviderType;
}
