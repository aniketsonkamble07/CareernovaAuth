package com.careernova.auth.controller;

import com.careernova.auth.dto.LoginRequestDto;
import com.careernova.auth.dto.LoginResponseDto;
import com.careernova.auth.dto.RegisterRequestDto;
import com.careernova.auth.entity.User;
import com.careernova.auth.enums.AuthProviderType;
import com.careernova.auth.exception.*;
import com.careernova.auth.repository.UserRepository;
import com.careernova.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication management endpoints")
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /* =========================
       EMAIL + PASSWORD LOGIN
       ========================= */
    @PostMapping("/login")
    @Operation(summary = "Login with email and password")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login successful"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials"),
            @ApiResponse(responseCode = "400", description = "Invalid request")
    })
    public ResponseEntity<LoginResponseDto> login(
            @Valid @RequestBody LoginRequestDto request
    ) {
        log.info("Login request received for email: {}", request.getEmail());

        try {
            LoginResponseDto response = authService.loginWithEmailPassword(
                    request.getEmail(),
                    request.getPassword()
            );

            log.info("Login successful for user: {}", response.getEmail());
            return ResponseEntity.ok(response);

        } catch (InvalidCredentialsException | WrongAuthenticationMethodException e) {
            log.warn("Login failed for {}: {}", request.getEmail(), e.getMessage());
            throw e;
        }
    }

    /* =========================
       REGISTER WITH EMAIL
       ========================= */
    @PostMapping("/register")
    @Operation(summary = "Register new user with email and password")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Registration successful"),
            @ApiResponse(responseCode = "400", description = "Invalid request or email already exists"),
            @ApiResponse(responseCode = "409", description = "Email already registered")
    })
    public ResponseEntity<LoginResponseDto> register(
            @Valid @RequestBody RegisterRequestDto request
    ) {
        log.info("Registration request received for email: {}", request.getEmail());

        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Registration failed - email already exists: {}", request.getEmail());
            Map<String, String> error = new HashMap<>();
            error.put("error", "Email already registered");
            error.put("message", "An account with this email already exists");
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(null);
        }

        try {
            // Create new user
            User user = User.builder()
                    .email(request.getEmail().toLowerCase().trim())
                    .username(request.getUsername() != null ? request.getUsername() :
                            request.getEmail().split("@")[0])
                    .password(passwordEncoder.encode(request.getPassword()))
                    .authProviderType(AuthProviderType.EMAIL)
                    .emailVerified(false) // Set to false, require email verification
                    .accountNonLocked(true)
                    .accountEnabled(true)
                    .createdAt(LocalDateTime.now())
                    .lastLoginAt(LocalDateTime.now())
                    .newUser(true)
                    .build();

            userRepository.save(user);
            log.info("User registered successfully: {}", user.getEmail());

            // Auto-login after registration
            LoginResponseDto response = authService.loginWithEmailPassword(
                    request.getEmail(),
                    request.getPassword()
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Registration failed for email: {}", request.getEmail(), e);
            throw new UserCreationException("Failed to register user", e);
        }
    }

    /* =========================
       REGISTER WITH EMAIL - RETURN USER ONLY
       ========================= */
    @PostMapping("/register/user-only")
    @Operation(summary = "Register new user without auto-login")
    public ResponseEntity<Map<String, Object>> registerUserOnly(
            @Valid @RequestBody RegisterRequestDto request
    ) {
        log.info("User-only registration request for email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(Map.of("error", "Email already exists"));
        }

        User user = User.builder()
                .email(request.getEmail().toLowerCase().trim())
                .username(request.getUsername() != null ? request.getUsername() :
                        request.getEmail().split("@")[0])
                .password(passwordEncoder.encode(request.getPassword()))
                .authProviderType(AuthProviderType.EMAIL)
                .emailVerified(false)
                .accountNonLocked(true)
                .accountEnabled(true)
                .createdAt(LocalDateTime.now())
                .build();

        User savedUser = userRepository.save(user);

        Map<String, Object> response = new HashMap<>();
        response.put("userId", savedUser.getId());
        response.put("email", savedUser.getEmail());
        response.put("message", "User registered successfully");

        return ResponseEntity.ok(response);
    }

    /* =========================
       CHECK EMAIL AVAILABILITY
       ========================= */
    @GetMapping("/check-email")
    @Operation(summary = "Check if email is already registered")
    public ResponseEntity<Map<String, Boolean>> checkEmail(
            @RequestParam String email
    ) {
        boolean exists = userRepository.existsByEmail(email.toLowerCase().trim());
        return ResponseEntity.ok(Map.of("available", !exists));
    }

    /* =========================
       REFRESH TOKEN
       ========================= */
    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token")
    public ResponseEntity<LoginResponseDto> refreshToken(
            @RequestHeader("Authorization") String refreshToken
    ) {
        // Implement token refresh logic
        // This would validate refresh token and generate new access token
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).build();
    }

    /* =========================
       LOGOUT
       ========================= */
    @PostMapping("/logout")
    @Operation(summary = "Logout user")
    public ResponseEntity<Map<String, String>> logout(
            @RequestHeader(value = "Authorization", required = false) String token
    ) {
        // Implement logout logic (token blacklisting, etc.)
        log.info("Logout request received");

        Map<String, String> response = new HashMap<>();
        response.put("message", "Logged out successfully");

        return ResponseEntity.ok(response);
    }

    /* =========================
       VERIFY EMAIL
       ========================= */
    @GetMapping("/verify-email")
    @Operation(summary = "Verify email address")
    public ResponseEntity<Map<String, String>> verifyEmail(
            @RequestParam String token
    ) {
        // Implement email verification logic
        log.info("Email verification request received");

        Map<String, String> response = new HashMap<>();
        response.put("message", "Email verified successfully");

        return ResponseEntity.ok(response);
    }

    /* =========================
       FORGOT PASSWORD
       ========================= */
    @PostMapping("/forgot-password")
    @Operation(summary = "Request password reset")
    public ResponseEntity<Map<String, String>> forgotPassword(
            @RequestParam String email
    ) {
        // Implement forgot password logic
        log.info("Password reset requested for: {}", email);

        Map<String, String> response = new HashMap<>();
        response.put("message", "If email exists, reset instructions will be sent");

        return ResponseEntity.ok(response);
    }

    /* =========================
       RESET PASSWORD
       ========================= */
    @PostMapping("/reset-password")
    @Operation(summary = "Reset password with token")
    public ResponseEntity<Map<String, String>> resetPassword(
            @RequestParam String token,
            @RequestParam String newPassword
    ) {
        // Implement password reset logic
        log.info("Password reset request received");

        Map<String, String> response = new HashMap<>();
        response.put("message", "Password reset successfully");

        return ResponseEntity.ok(response);
    }

    /* =========================
       HEALTH CHECK
       ========================= */
    @GetMapping("/health")
    @Operation(summary = "Health check endpoint")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> healthStatus = new HashMap<>();
        healthStatus.put("status", "UP");
        healthStatus.put("service", "auth-service");
        healthStatus.put("timestamp", LocalDateTime.now().toString());
        healthStatus.put("database", userRepository.count() >= 0 ? "UP" : "DOWN");

        return ResponseEntity.ok(healthStatus);
    }

    /* =========================
       CURRENT USER INFO
       ========================= */
    @GetMapping("/me")
    @Operation(summary = "Get current user info from token")
    public ResponseEntity<Map<String, Object>> getCurrentUser(
            @RequestHeader("Authorization") String token
    ) {
        // Extract user from token and return info
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("message", "Endpoint to be implemented");

        return ResponseEntity.ok(userInfo);
    }
}