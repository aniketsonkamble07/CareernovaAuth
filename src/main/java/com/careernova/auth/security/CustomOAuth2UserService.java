package com.careernova.auth.security;

import com.careernova.auth.enums.AuthProviderType;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest)
            throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId =
                userRequest.getClientRegistration()
                        .getRegistrationId()
                        .toLowerCase();

        AuthProviderType providerType =
                OAuthUtil.getAuthProviderTypeFromRegistrationId(registrationId);

        Map<String, Object> attributes =
                new HashMap<>(oAuth2User.getAttributes());

        // Normalize attributes across providers
        normalizeAttributes(attributes, providerType);

        return new CustomOAuth2User(
                attributes,
                "id" // common key
        );
    }

    private void normalizeAttributes(
            Map<String, Object> attributes,
            AuthProviderType providerType
    ) {

        switch (providerType) {

            case GOOGLE -> {
                attributes.put("id", attributes.get("sub"));
                attributes.put("email", attributes.get("email"));
                attributes.put("name", attributes.get("name"));
                attributes.put("picture", attributes.get("picture"));
            }

            case GITHUB -> {
                attributes.put("id", attributes.get("id"));
                attributes.put("email", attributes.get("email"));
                attributes.put("name", attributes.get("login"));
                attributes.put("picture", attributes.get("avatar_url"));
            }

            default -> throw new IllegalArgumentException(
                    "Unsupported provider: " + providerType
            );
        }
    }
}
