package com.careernova.auth.security;

import com.careernova.auth.dto.LoginResponseDto;
import com.careernova.auth.enums.AuthProviderType;
import com.careernova.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final AuthService authService;

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

        normalizeAttributes(attributes, providerType);

        LoginResponseDto loginResponse =
                authService.processOAuthLogin(attributes, providerType);

        attributes.put("jwt", loginResponse.getAccessToken());
        attributes.put("newUser", loginResponse.isNewUser());

        return new CustomOAuth2User(attributes, "id");
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