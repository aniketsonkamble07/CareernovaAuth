package com.careernova.auth.exception;

import com.careernova.auth.enums.AuthProviderType;

public class OAuthAuthenticationException extends RuntimeException {
    private final AuthProviderType provider;

    public OAuthAuthenticationException(AuthProviderType provider, String message) {
        super(message);
        this.provider = provider;
    }

    public AuthProviderType getProvider() { return provider; }
}





