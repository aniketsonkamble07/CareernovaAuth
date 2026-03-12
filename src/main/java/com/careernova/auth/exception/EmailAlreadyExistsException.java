package com.careernova.auth.exception;

import com.careernova.auth.enums.AuthProviderType;
import lombok.Getter;

@Getter
public class EmailAlreadyExistsException extends RuntimeException {
    private final String email;
    private final AuthProviderType existingProvider;
    private final AuthProviderType attemptedProvider;

    public EmailAlreadyExistsException(String email, AuthProviderType existing, AuthProviderType attempted) {
        super(String.format("Email %s already registered with %s", email, existing));
        this.email = email;
        this.existingProvider = existing;
        this.attemptedProvider = attempted;
    }
}
