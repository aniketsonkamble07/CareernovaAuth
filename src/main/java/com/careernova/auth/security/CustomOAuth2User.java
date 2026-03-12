package com.careernova.auth.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

public class CustomOAuth2User implements OAuth2User {

    private final Map<String, Object> attributes;
    private final String nameAttributeKey;
    private final String registrationId;

    public CustomOAuth2User(Map<String, Object> attributes, String nameAttributeKey, String registrationId) {
        this.attributes = Collections.unmodifiableMap(attributes);
        this.nameAttributeKey = nameAttributeKey != null ? nameAttributeKey : "email";
        this.registrationId = registrationId;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public String getName() {
        Object name = attributes.get(nameAttributeKey);
        return name != null ? String.valueOf(name) : "";
    }

    public String getId() {
        return switch (registrationId) {
            case "google" -> getAttributeAsString("id");
            case "github" -> getAttributeAsString("id");
            case "facebook" -> getAttributeAsString("id");
            default -> getAttributeAsString("id");
        };
    }

    public String getEmail() {
        return getAttributeAsString("email");
    }

    public String getNameValue() {
        String name = switch (registrationId) {
            case "google" -> getAttributeAsString("name");
            case "github" -> getAttributeAsString("name");
            case "facebook" -> getAttributeAsString("name");
            default -> getAttributeAsString("name");
        };
        return Optional.ofNullable(name).orElse(getEmail());
    }

    public String getPicture() {
        return getAttributeAsString("picture");
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public boolean isEmailVerified() {
        Object verified = attributes.get("email_verified");
        if (verified instanceof Boolean) return (Boolean) verified;
        if (verified instanceof String) return Boolean.parseBoolean((String) verified);
        return false;
    }

    private String getAttributeAsString(String key) {
        Object value = attributes.get(key);
        return value != null ? String.valueOf(value) : null;
    }

    @Override
    public String toString() {
        return String.format("CustomOAuth2User{registrationId='%s', email='%s', name='%s'}",
                registrationId, getEmail(), getNameValue());
    }
}