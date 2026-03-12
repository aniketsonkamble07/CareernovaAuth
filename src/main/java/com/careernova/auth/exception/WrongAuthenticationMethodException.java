package com.careernova.auth.exception;

public class WrongAuthenticationMethodException extends RuntimeException {
    public WrongAuthenticationMethodException(String message) { super(message); }
}
