package com.careernova.auth.service;

import com.careernova.auth.dto.LoginResponseDto;
import com.careernova.auth.entity.User;
import com.careernova.auth.enums.AuthProviderType;
import com.careernova.auth.repository.UserRepository;
import com.careernova.auth.security.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

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
    public LoginResponseDto processOAuthLogin(
            Map<String, Object> attributes,
            AuthProviderType providerType
    ) {

        String providerId = null;
        String email = (String) attributes.get("email");

        switch (providerType) {

            case GOOGLE:
                // Google OIDC uses "sub"
                providerId = (String) attributes.get("sub");
                break;

            case GITHUB:
                // GitHub uses "id"
                Object githubId = attributes.get("id");
                if (githubId != null) {
                    providerId = githubId.toString();
                }
                break;

            default:
                throw new RuntimeException("Unsupported provider");
        }

        if (providerId == null || email == null) {
            throw new RuntimeException("Invalid OAuth provider data");
        }

        User user = userRepository
                .findByAuthProviderTypeAndProviderId(providerType, providerId)
                .orElse(null);

        boolean isNewUser = false;

        if (user == null) {

            if (userRepository.existsByEmail(email)) {
                throw new RuntimeException(
                        "Email already registered using another login method"
                );
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

        return LoginResponseDto.builder()
                .accessToken(jwt)
                .tokenType("Bearer")
                .expiresIn(3600)
                .userId(user.getId())
                .email(user.getEmail())
                .providerType(user.getAuthProviderType())
                .newUser(isNewUser)
                .build();
    }
    /* =========================
   EMAIL + PASSWORD LOGIN
   ========================= */
    public LoginResponseDto loginWithEmailPassword(String email, String rawPassword) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new RuntimeException("Invalid email or password")
                );

        if (user.getAuthProviderType() != AuthProviderType.EMAIL) {
            throw new RuntimeException(
                    "Please login using " + user.getAuthProviderType()
            );
        }

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new RuntimeException("Invalid email or password");
        }

        String jwt = jwtService.generateToken(user.getEmail());

        return LoginResponseDto.builder()
                .accessToken(jwt)
                .tokenType("Bearer")
                .expiresIn(3600)
                .userId(user.getId())
                .email(user.getEmail())
                .providerType(AuthProviderType.EMAIL)
                .newUser(false)
                .build();
    }
}