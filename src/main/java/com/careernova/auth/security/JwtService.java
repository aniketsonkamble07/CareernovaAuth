package com.careernova.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;


@Service
public class JwtService {

    private final Key key;
    private final long EXPIRATION_TIME = 15 * 60 * 1000;

    public JwtService(@Value("${jwt.secret}") String secret) {
        System.out.println("JWT Secret Loaded: " + secret);
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateToken(String username) {
        System.out.println("Generating JWT for user: " + username);

        String token = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        System.out.println("Generated Token: " + token);
        return token;
    }

    public String getUserNameFromAccessToken(String token) {

        System.out.println("Parsing token: " + token);

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            System.out.println("Token subject: " + claims.getSubject());
            System.out.println("Token expiration: " + claims.getExpiration());

            return claims.getSubject();

        } catch (Exception e) {
            System.out.println("JWT parsing failed ❌");
            System.out.println("Reason: " + e.getMessage());
            return null;
        }
    }

    public boolean isTokenValid(String token) {
        boolean valid = getUserNameFromAccessToken(token) != null;
        System.out.println("Token valid check: " + valid);
        return valid;
    }
}
