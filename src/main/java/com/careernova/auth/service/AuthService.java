package com.careernova.auth.service;

import com.careernova.auth.dto.LoginResponseDto;
import com.careernova.auth.entity.User;
import com.careernova.auth.enums.AuthProviderType;
import com.careernova.auth.exception.*;
import com.careernova.auth.repository.UserRepository;
import com.careernova.auth.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.access-token.expiration:3600000}")
    private long accessTokenExpiration;

    /* =========================
       OAuth2 LOGIN
       ========================= */
    @Transactional
    public LoginResponseDto processOAuthLogin(
            Map<String, Object> attributes,
            AuthProviderType providerType
    ) {
        log.debug("Processing OAuth login for provider: {}", providerType);

        try {
            // Extract provider-specific user ID
            String providerId = extractProviderId(attributes, providerType);

            // Extract email with validation
            String email = extractAndValidateEmail(attributes, providerType);

            if (providerId == null || email == null) {
                log.error("Missing required OAuth attributes for provider: {}", providerType);
                throw new OAuthAuthenticationException(
                        providerType,
                        "Invalid OAuth provider data: missing required attributes"
                );
            }

            // Find or create user
            User user = findOrCreateOAuthUser(providerType, providerId, email, attributes);

            // Update last login time
            user.setLastLoginAt(LocalDateTime.now());
            userRepository.save(user);

            // Generate JWT token
            String jwt = jwtService.generateAccessToken(user.getEmail());

            log.info("OAuth login successful for user: {}, provider: {}, newUser: {}",
                    user.getEmail(), providerType, user.isNewUser());

            LoginResponseDto loginResponse = LoginResponseDto.builder()
                    .accessToken(jwt)
                    .refreshToken(null)
                    .tokenType("Bearer")
                    .expiresIn(accessTokenExpiration / 1000)
                    .userId(user.getId())
                    .email(user.getEmail())
                    .provider(providerType)
                    .providerUserId(providerId)
                    .newUser(user.isNewUser())
                    .onboardingRequired(user.isNewUser())
                    .build();

            return loginResponse;

        } catch (Exception e) {
            log.error("OAuth login failed for provider: {}", providerType, e);
            throw e;
        }
    }

    private String extractProviderId(Map<String, Object> attributes, AuthProviderType providerType) {
        return switch (providerType) {
            case GOOGLE -> Optional.ofNullable(attributes.get("sub"))
                    .map(Object::toString)
                    .orElseThrow(() -> new OAuthAuthenticationException(
                            providerType, "Missing 'sub' attribute for Google OAuth"));

            case GITHUB -> Optional.ofNullable(attributes.get("id"))
                    .map(Object::toString)
                    .orElseThrow(() -> new OAuthAuthenticationException(
                            providerType, "Missing 'id' attribute for GitHub OAuth"));

            case FACEBOOK -> Optional.ofNullable(attributes.get("id"))
                    .map(Object::toString)
                    .orElseThrow(() -> new OAuthAuthenticationException(
                            providerType, "Missing 'id' attribute for Facebook OAuth"));

            default -> throw new UnsupportedProviderException(providerType);
        };
    }

    private String extractAndValidateEmail(Map<String, Object> attributes, AuthProviderType providerType) {
        String email = (String) attributes.get("email");

        if (email == null || email.trim().isEmpty()) {
            throw new OAuthAuthenticationException(
                    providerType,
                    "Email not provided by OAuth provider"
            );
        }

        if (!isValidEmail(email)) {
            throw new OAuthAuthenticationException(
                    providerType,
                    "Invalid email format from OAuth provider"
            );
        }

        return email.toLowerCase().trim();
    }

    private boolean isValidEmail(String email) {
        return email != null && email.matches("^[A-Za-z0-9+_.-]+@(.+)$");
    }

    @Transactional
    protected User findOrCreateOAuthUser(
            AuthProviderType providerType,
            String providerId,
            String email,
            Map<String, Object> attributes
    ) {
        return userRepository
                .findByAuthProviderTypeAndProviderId(providerType, providerId)
                .orElseGet(() -> {
                    Optional<User> existingUserByEmail = userRepository.findByEmail(email);

                    if (existingUserByEmail.isPresent()) {
                        User existingUser = existingUserByEmail.get();

                        if (existingUser.getAuthProviderType() != providerType) {
                            log.warn("Email {} already registered with provider: {}",
                                    email, existingUser.getAuthProviderType());
                            throw new EmailAlreadyExistsException(
                                    email,
                                    existingUser.getAuthProviderType(),
                                    providerType
                            );
                        }
                        return existingUser;
                    }

                    // Create new user with all fields initialized
                    User newUser = User.builder()
                            .email(email)
                            .username(generateUsername(email, providerType))
                            .authProviderType(providerType)
                            .providerId(providerId)
                            .emailVerified(isEmailVerified(attributes, providerType))
                            .accountNonLocked(true)
                            .accountEnabled(true)
                            .createdAt(LocalDateTime.now())
                            .lastLoginAt(LocalDateTime.now())
                            .newUser(true)
                            .build();

                    // Extra safety - ensure no nulls
                    if (newUser.getAccountEnabled() == null) newUser.setAccountEnabled(true);
                    if (newUser.getAccountNonLocked() == null) newUser.setAccountNonLocked(true);
                    if (newUser.getEmailVerified() == null) newUser.setEmailVerified(false);

                    try {
                        User savedUser = userRepository.save(newUser);
                        log.info("Created new user from {} OAuth: {}", providerType, email);
                        return savedUser;
                    } catch (DataIntegrityViolationException e) {
                        log.error("Data integrity violation while creating user: {}", email, e);
                        throw new UserCreationException("Failed to create user due to duplicate data", e);
                    }
                });
    }

    private String generateUsername(String email, AuthProviderType providerType) {
        String base = email.split("@")[0];
        String suffix = providerType.name().toLowerCase();
        return base + "_" + suffix;
    }

    private boolean isEmailVerified(Map<String, Object> attributes, AuthProviderType providerType) {
        return switch (providerType) {
            case GOOGLE -> Optional.ofNullable(attributes.get("email_verified"))
                    .map(v -> v.equals(true) || v.equals("true"))
                    .orElse(false);
            case GITHUB -> true;
            case FACEBOOK -> Optional.ofNullable(attributes.get("verified"))
                    .map(v -> v.equals(true) || v.equals("true"))
                    .orElse(false);
            default -> false;
        };
    }

    /* =========================
       EMAIL + PASSWORD LOGIN
       ========================= */
    @Transactional(readOnly = true)
    public LoginResponseDto loginWithEmailPassword(String email, String rawPassword) {
        log.debug("Processing email/password login for: {}", email);

        try {
            User user = userRepository.findByEmail(email.toLowerCase().trim())
                    .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

            // Check if user is using correct auth method
            if (user.getAuthProviderType() != AuthProviderType.EMAIL) {
                log.warn("User {} attempted email login but uses {}", email, user.getAuthProviderType());
                throw new WrongAuthenticationMethodException(
                        "Please login using " + user.getAuthProviderType()
                );
            }

            // Check account status - USING HELPER METHODS
            if (!user.isEnabled()) {
                throw new AccountDisabledException("Account is disabled");
            }

            if (!user.isNonLocked()) {
                throw new AccountLockedException("Account is locked");
            }

            // Validate password
            if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
                log.warn("Failed login attempt for user: {}", email);
                throw new InvalidCredentialsException("Invalid email or password");
            }

            // Update last login
            user.setLastLoginAt(LocalDateTime.now());
            userRepository.save(user);

            // Generate JWT
            String jwt = jwtService.generateAccessToken(user.getEmail());

            log.info("Email/password login successful for user: {}", email);

            return LoginResponseDto.builder()
                    .accessToken(jwt)
                    .tokenType("Bearer")
                    .expiresIn(accessTokenExpiration / 1000)
                    .userId(user.getId())
                    .email(user.getEmail())
                    .provider(AuthProviderType.EMAIL)
                    .newUser(false)
                    .onboardingRequired(false)
                    .build();

        } catch (Exception e) {
            log.error("Login failed for email: {}", email, e);
            throw e;
        }
    }
}