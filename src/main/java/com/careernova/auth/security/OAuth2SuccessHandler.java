package com.careernova.auth.security;

import com.careernova.auth.dto.LoginResponseDto;
import com.careernova.auth.enums.AuthProviderType;
import com.careernova.auth.service.AuthService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final AuthService authService;

    public OAuth2SuccessHandler(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        Map<String, Object> attributes = oAuth2User.getAttributes();

        String registrationId =
                ((OAuth2AuthenticationToken) authentication)
                        .getAuthorizedClientRegistrationId();

        AuthProviderType providerType =
                OAuthUtil.getAuthProviderTypeFromRegistrationId(registrationId);

        LoginResponseDto loginResponse =
                authService.processOAuthLogin(attributes, providerType);

        String jwt = loginResponse.getAccessToken();

        if (loginResponse.isNewUser()) {
            response.sendRedirect("http://localhost:8081/update-profile?token=" + jwt);
        } else {
            response.sendRedirect("http://localhost:8081/home?token=" + jwt);
        }
    }
}