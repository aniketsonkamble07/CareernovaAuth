package com.careernova.auth.security;

import com.careernova.auth.enums.AuthProviderType;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Objects;

public class OAuthUtil {

    public static AuthProviderType getAuthProviderTypeFromRegistrationId(String registrationId) {

        return switch (registrationId.toLowerCase()) {
            case "google" -> AuthProviderType.GOOGLE;
            case "github" -> AuthProviderType.GITHUB;
            case "twitter" -> AuthProviderType.TWITTER;
            default ->
                    throw new IllegalArgumentException(
                            "Unsupported OAuth2 provider: " + registrationId
                    );
        };
    }

    public static String determineProviderUserId(OAuth2User user,String registrationId )
    {

        return switch (registrationId.toLowerCase())
        {

            // Google unique identifier
            case "google" ->
                    Objects.requireNonNull(
                            user.getAttribute("sub"),
                            "Google OAuth2 'sub' attribute is missing"
                    );

            // GitHub numeric user id
            case "github" ->
                    Objects.requireNonNull(
                            user.getAttribute("id"),
                            "GitHub OAuth2 'id' attribute is missing"
                    ).toString();

            default ->
                    throw new IllegalArgumentException(
                            "Unsupported OAuth2 provider: " + registrationId
                    );
        };
    }
}
