package com.careernova.auth.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class CustomOAuth2User implements OAuth2User {

    private final Map<String, Object> attributes;
    private final String nameAttributeKey;

    public CustomOAuth2User(
            Map<String, Object> attributes,
            String nameAttributeKey
    ) {
        this.attributes = attributes;
        this.nameAttributeKey = nameAttributeKey;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(); // roles handled via JWT later
    }

    @Override
    public String getName() {
        return String.valueOf(attributes.get(nameAttributeKey));
    }

    // Convenience getters
    public String getId() {
        return String.valueOf(attributes.get("id"));
    }

    public String getEmail() {
        return (String) attributes.get("email");
    }

    public String getNameValue() {
        return (String) attributes.get("name");
    }

    public String getPicture() {
        return (String) attributes.get("picture");
    }
}
