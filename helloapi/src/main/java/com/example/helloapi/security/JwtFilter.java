package com.example.helloapi.security;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.helloapi.model.AppUser;
import com.example.helloapi.repository.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwt;
    private final UserRepository users;

    public JwtFilter(JwtService jwt, UserRepository users) {
        this.jwt = jwt;
        this.users = users;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();

        // Bài thực hành bảo vệ hai đường dẫn này.
        return !("/hello".equals(path) || "/auth".equals(path));
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String authorization = request.getHeader("Authorization");

        if (authorization == null
                || !authorization.startsWith("Bearer ")) {
            reject(response, "Thieu Bearer token");
            return;
        }

        String token = authorization.substring(7).trim();

        DecodedJWT decoded;

        try {
            decoded = jwt.verifyToken(token);
        } catch (JWTVerificationException | IllegalArgumentException ex) {
            reject(response, "Token khong hop le hoac da het han");
            return;
        }

        String userName = decoded.getSubject();

        if (userName == null || userName.isBlank()) {
            reject(response, "Token khong co thong tin nguoi dung");
            return;
        }

        AppUser user = users.findByUserName(userName).orElse(null);

        if (user == null || !token.equals(user.token())) {
            reject(response, "Token khong con duoc chap nhan");
            return;
        }

        request.setAttribute("userName", user.userName());

        // JWT hợp lệ: cho yêu cầu đi tiếp đến Controller.
        filterChain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, String message)
            throws IOException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        response.getWriter().write(
                "{\"message\":\"" + message + "\"}");
    }
}