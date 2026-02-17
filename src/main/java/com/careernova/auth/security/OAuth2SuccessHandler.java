package com.careernova.auth.security;

import com.careernova.auth.enums.AuthProviderType;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@AllArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final OAuth2AuthorizedClientService authorizedClientService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        OAuth2AuthenticationToken authToken =
                (OAuth2AuthenticationToken) authentication;

        OAuth2User oAuth2User = authToken.getPrincipal();

        String registrationId =
                authToken.getAuthorizedClientRegistrationId();

        // ✅ Get provider type
        AuthProviderType provider =
                OAuthUtil.getAuthProviderTypeFromRegistrationId(registrationId);

        // ✅ Get provider user id
        String providerUserId =
                OAuthUtil.determineProviderUserId(oAuth2User, registrationId);

        // ✅ Load authorized client (THIS is where token lives)
        OAuth2AuthorizedClient authorizedClient =
                authorizedClientService.loadAuthorizedClient(
                        registrationId,
                        authToken.getName()
                );

        OAuth2AccessToken accessToken =
                authorizedClient.getAccessToken();

        // ---- DEBUG (temporary) ----
        System.out.println("Provider = " + provider);
        System.out.println("Provider User ID = " + providerUserId);
        System.out.println("Access Token = " + accessToken.getTokenValue());

        // TODO:
        // 1. Save / update user in DB
        // 2. Generate JWT
        // 3. Redirect to frontend

        response.sendRedirect("/login/success");
    }
}
