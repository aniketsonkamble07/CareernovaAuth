package com.careernova.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
        System.out.println("✅ JwtAuthenticationFilter CONSTRUCTED");
    }
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        String path = request.getServletPath();

        return path.startsWith("/login")
                || path.startsWith("/oauth2")
                || path.startsWith("/auth")
                || path.startsWith("/error")
                || path.startsWith("/default-ui.css")
                || path.startsWith("/favicon.ico")
                || path.startsWith("/swagger")
                || path.startsWith("/v3/api-docs");
    }


    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        System.out.println("\n🔍 JwtAuthenticationFilter CALLED");
        System.out.println("➡ Request URI: " + request.getRequestURI());

        var existingAuth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("➡ Existing Authentication: " + existingAuth);

        String authHeader = request.getHeader("Authorization");
        System.out.println("➡ Authorization Header: " + authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            System.out.println("❌ No Bearer token found");
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        System.out.println("➡ Extracted Token: " + token);

        boolean valid = jwtService.isTokenValid(token);
        System.out.println("➡ Token valid? " + valid);

        if (!valid) {
            System.out.println("❌ INVALID TOKEN");
            filterChain.doFilter(request, response);
            return;
        }

        String username = jwtService.getUserNameFromAccessToken(token);
        System.out.println("➡ Username from token: " + username);

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        Collections.emptyList()
                );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        System.out.println("✅ Authentication SET in SecurityContext");

        filterChain.doFilter(request, response);
    }
}
