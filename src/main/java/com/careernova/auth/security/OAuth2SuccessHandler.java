package com.careernova.auth.security;

import com.careernova.auth.dto.LoginResponseDto;
import com.careernova.auth.enums.AuthProviderType;
import com.careernova.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
@Slf4j
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

        if (!(authentication instanceof OAuth2AuthenticationToken)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unsupported authentication type");
            return;
        }

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauthToken.getPrincipal();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String registrationId = oauthToken.getAuthorizedClientRegistrationId();
        AuthProviderType providerType = OAuthUtil.getAuthProviderTypeFromRegistrationId(registrationId);

        LoginResponseDto loginResponse = authService.processOAuthLogin(attributes, providerType);
        String jwt = URLEncoder.encode(loginResponse.getAccessToken(), StandardCharsets.UTF_8);

        log.info("OAuth2 login success for provider: {}, email: {}", providerType, loginResponse.getEmail());

        if (loginResponse.isNewUser()) {
            response.sendRedirect("http://localhost:8081/update-profile?token=" + jwt);
        } else {
            response.sendRedirect("http://localhost:8081/home?token=" + jwt);
        }
    }
}