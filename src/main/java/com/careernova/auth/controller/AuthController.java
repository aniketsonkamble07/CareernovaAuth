package com.careernova.auth.controller;



import com.careernova.auth.dto.LoginRequestDto;
import com.careernova.auth.dto.LoginResponseDto;
import com.careernova.auth.dto.RegisterRequestDto;
import com.careernova.auth.entity.User;
import com.careernova.auth.enums.AuthProviderType;
import com.careernova.auth.repository.UserRepository;
import com.careernova.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /* =========================
       EMAIL + PASSWORD LOGIN
       ========================= */
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(
            @RequestBody LoginRequestDto request
    ) {
        LoginResponseDto response =
                authService.loginWithEmailPassword(
                        request.getEmail(),
                        request.getPassword()
                );

        return ResponseEntity.ok(response);
    }

    /* =========================
       REGISTER WITH EMAIL
       =========================
    @PostMapping("/register")
    public ResponseEntity<LoginResponseDto> register(
            @RequestBody RegisterRequestDto request
    ) {

        if (userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest()
                    .body(null);
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setUsername(request.getEmail());
        user.setPassword(
                passwordEncoder.encode(request.getPassword())
        );
        user.setAuthProviderType(AuthProviderType.EMAIL);

        userRepository.save(user);

        LoginResponseDto response =
                authService.loginWithEmailPassword(
                        request.getEmail(),
                        request.getPassword()
                );

        return ResponseEntity.ok(response);
    }
 */
    /* =========================
       HEALTH CHECK
       ========================= */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Auth service is running 🚀");
    }
}