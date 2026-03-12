package com.careernova.auth.security;

import com.careernova.auth.enums.AuthProviderType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class OAuthUtil {

    private static final Map<String, AuthProviderType> PROVIDER_MAP = new ConcurrentHashMap<>();

    static {
        PROVIDER_MAP.put("google", AuthProviderType.GOOGLE);
        PROVIDER_MAP.put("github", AuthProviderType.GITHUB);
        PROVIDER_MAP.put("twitter", AuthProviderType.TWITTER);
        PROVIDER_MAP.put("facebook", AuthProviderType.FACEBOOK);
        PROVIDER_MAP.put("linkedin", AuthProviderType.LINKEDIN);
        PROVIDER_MAP.put("microsoft", AuthProviderType.MICROSOFT);
    }

    public static AuthProviderType getAuthProviderTypeFromRegistrationId(String registrationId) {
        if (registrationId == null || registrationId.trim().isEmpty()) {
            throw new IllegalArgumentException("Registration ID cannot be null or empty");
        }

        AuthProviderType provider = PROVIDER_MAP.get(registrationId.toLowerCase());

        if (provider == null) {
            log.error("Unsupported OAuth2 provider: {}", registrationId);
            throw new IllegalArgumentException(
                    "Unsupported OAuth2 provider: " + registrationId +
                            ". Supported providers: " + PROVIDER_MAP.keySet()
            );
        }

        log.debug("Mapped registrationId '{}' to provider: {}", registrationId, provider);
        return provider;
    }

    public static String determineProviderUserId(OAuth2User user, String registrationId) {
        Objects.requireNonNull(user, "OAuth2User cannot be null");
        Objects.requireNonNull(registrationId, "Registration ID cannot be null");

        String providerId = switch (registrationId.toLowerCase()) {
            case "google" -> extractGoogleUserId(user);
            case "github" -> extractGitHubUserId(user);
            case "facebook" -> extractFacebookUserId(user);
            case "twitter" -> extractTwitterUserId(user);
            case "linkedin" -> extractLinkedInUserId(user);
            default -> throw new IllegalArgumentException(
                    "Unsupported OAuth2 provider for user ID extraction: " + registrationId
            );
        };

        log.debug("Extracted user ID '{}' for provider: {}", providerId, registrationId);
        return providerId;
    }

    private static String extractGoogleUserId(OAuth2User user) {
        String sub = user.getAttribute("sub");
        return Objects.requireNonNull(sub, "Google OAuth2 'sub' attribute is missing");
    }

    private static String extractGitHubUserId(OAuth2User user) {
        Object id = user.getAttribute("id");
        Objects.requireNonNull(id, "GitHub OAuth2 'id' attribute is missing");

        if (id instanceof Number) {
            return String.valueOf(((Number) id).longValue());
        }
        return id.toString();
    }

    private static String extractFacebookUserId(OAuth2User user) {
        Object id = user.getAttribute("id");
        Objects.requireNonNull(id, "Facebook OAuth2 'id' attribute is missing");
        return id.toString();
    }

    private static String extractTwitterUserId(OAuth2User user) {
        Object id = user.getAttribute("id");
        Objects.requireNonNull(id, "Twitter OAuth2 'id' attribute is missing");
        return id.toString();
    }

    private static String extractLinkedInUserId(OAuth2User user) {
        String sub = user.getAttribute("sub");
        return Objects.requireNonNull(sub, "LinkedIn OAuth2 'sub' attribute is missing");
    }

    public static String getProviderSpecificNameAttribute(String registrationId) {
        return switch (registrationId.toLowerCase()) {
            case "google", "linkedin", "facebook" -> "name";
            case "github" -> "login";
            case "twitter" -> "screen_name";
            default -> "name";
        };
    }

    public static String getProviderSpecificEmailAttribute(String registrationId) {
        return switch (registrationId.toLowerCase()) {
            case "google", "facebook", "linkedin" -> "email";
            case "github" -> "email"; // Note: GitHub may require additional email endpoint
            default -> "email";
        };
    }

    public static boolean isProviderSupported(String registrationId) {
        return registrationId != null && PROVIDER_MAP.containsKey(registrationId.toLowerCase());
    }
}