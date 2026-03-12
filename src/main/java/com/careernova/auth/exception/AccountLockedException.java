package com.careernova.auth.exception;

public class AccountLockedException extends RuntimeException {
    public AccountLockedException(String message) { super(message); }
}
