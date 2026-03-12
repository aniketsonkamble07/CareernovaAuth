package com.careernova.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequestDto {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;

    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username; // Optional

    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    private String firstName; // Optional

    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    private String lastName; // Optional
}