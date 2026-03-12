package com.careernova.auth.exception;

import com.careernova.auth.enums.AuthProviderType;

public class UnsupportedProviderException extends RuntimeException {
    public UnsupportedProviderException(AuthProviderType provider) {
        super("Unsupported OAuth provider: " + provider);
    }
}

