package com.careernova.auth.dto;

import com.careernova.auth.enums.AuthProviderType;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponseDto {

    // Authentication tokens
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("token_type")
    @Builder.Default
    private String tokenType = "Bearer";

    @JsonProperty("expires_in")
    private long expiresIn;

    // OAuth provider info
    @JsonProperty("provider")
    private AuthProviderType provider;

    @JsonProperty("provider_user_id")
    private String providerUserId;

    // User info (minimal, will be fetched from user service)
    @JsonProperty("user_id")
    private Long userId;  // ID from user service

    @JsonProperty("email")
    private String email;

    @JsonProperty("new_user")
    private boolean newUser;

    // For internal service communication
    @JsonProperty("service_token")
    private String serviceToken;  // Token for service-to-service calls

    // Metadata for frontend
    @JsonProperty("redirect_url")
    private String redirectUrl;

    @JsonProperty("onboarding_required")
    private boolean onboardingRequired;

    public static LoginResponseDto fromOAuthUser(
            String accessToken,
            String refreshToken,
            Long userId,
            String email,
            AuthProviderType provider,
            String providerUserId,
            boolean newUser
    ) {
        return LoginResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(3600)
                .userId(userId)
                .email(email)
                .provider(provider)
                .providerUserId(providerUserId)
                .newUser(newUser)
                .onboardingRequired(newUser) // New users need onboarding
                .build();
    }
}