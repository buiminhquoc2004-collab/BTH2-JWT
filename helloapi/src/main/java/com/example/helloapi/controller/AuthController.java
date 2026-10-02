package com.example.helloapi.controller;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.helloapi.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    public record LoginRequest(String userName, String password) {
    }

    @PostMapping("/")
    public Map<String, Object> login(@RequestBody LoginRequest request) {
        String token = authService.login(
                request.userName(),
                request.password());

        return Map.of(
                "token", token,
                "tokenType", "Bearer",
                "expiresIn", 3600);
    }

    @GetMapping("/auth")
    public Map<String, Object> auth(HttpServletRequest request) {
        return Map.of(
                "message", "Token hop le",
                "userName", request.getAttribute("userName"));
    }
}