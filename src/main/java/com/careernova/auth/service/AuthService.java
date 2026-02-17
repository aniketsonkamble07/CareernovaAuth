package com.careernova.auth.service;

import com.careernova.auth.dto.LoginResponseDto;
import com.careernova.auth.entity.User;
import com.careernova.auth.enums.AuthProviderType;
import com.careernova.auth.repository.UserRepository;
import com.careernova.auth.security.JwtService;
import com.careernova.auth.security.OAuthUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthService(
            UserRepository userRepository,
            JwtService jwtService,
            PasswordEncoder passwordEncoder
    ) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
    }

    /* =========================
       OAuth2 LOGIN
       ========================= */
    public ResponseEntity<?> handleOAuth2LoginRequest(
            OAuth2User oAuth2User,
            String registrationId
    ) {

        AuthProviderType providerType =
                OAuthUtil.getAuthProviderTypeFromRegistrationId(registrationId);

        String providerId =
                OAuthUtil.determineProviderUserId(oAuth2User, registrationId);

        if (providerId == null) {
            return ResponseEntity.badRequest()
                    .body("Invalid OAuth provider data");
        }

        User user = userRepository
                .findByAuthProviderTypeAndProviderId(providerType, providerId)
                .orElse(null);

        boolean isNewUser = false;

        if (user == null) {

            String email = oAuth2User.getAttribute("email");
            if (email == null) {
                return ResponseEntity.badRequest()
                        .body("Email not provided by OAuth provider");
            }

            if (userRepository.existsByEmail(email)) {
                return ResponseEntity.status(409)
                        .body("Email already registered using another login method");
            }

            user = new User();
            user.setEmail(email);
            user.setUsername(email);
            user.setAuthProviderType(providerType);
            user.setProviderId(providerId);

            user = userRepository.save(user);
            isNewUser = true;
        }

        String jwt = jwtService.generateToken(user.getEmail());

        return ResponseEntity.ok(
                LoginResponseDto.builder()
                        .accessToken(jwt)
                        .tokenType("Bearer")
                        .expiresIn(3600)
                        .userId(user.getId())
                        .email(user.getEmail())
                        .providerType(user.getAuthProviderType())
                        .newUser(isNewUser)
                        .build()
        );
    }

    /* =========================
       EMAIL + PASSWORD LOGIN
       ========================= */
    public ResponseEntity<?> handleEmailPasswordLogin(
            String email,
            String rawPassword
    ) {

        User user = userRepository.findByEmail(email)
                .orElse(null);

        if (user == null) {
            return ResponseEntity.status(401)
                    .body("Invalid email or password");
        }

        if (user.getAuthProviderType() != AuthProviderType.EMAIL) {
            return ResponseEntity.status(400)
                    .body("Please login using " + user.getAuthProviderType());
        }

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            return ResponseEntity.status(401)
                    .body("Invalid email or password");
        }

        String jwt = jwtService.generateToken(user.getEmail());

        return ResponseEntity.ok(
                LoginResponseDto.builder()
                        .accessToken(jwt)
                        .tokenType("Bearer")
                        .expiresIn(3600)
                        .userId(user.getId())
                        .email(user.getEmail())
                        .providerType(AuthProviderType.EMAIL)
                        .newUser(false)
                        .build()
        );
    }
}
