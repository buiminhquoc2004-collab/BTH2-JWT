package com.example.helloapi.service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.boot.CommandLineRunner;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.example.helloapi.model.AppUser;
import com.example.helloapi.repository.UserRepository;
import com.example.helloapi.security.JwtService;

@Service
public class AuthService implements CommandLineRunner {

    private final UserRepository users;
    private final JwtService jwt;
    private final BCryptPasswordEncoder encoder =
            new BCryptPasswordEncoder();

    public AuthService(UserRepository users, JwtService jwt) {
        this.users = users;
        this.jwt = jwt;
    }

    // Tạo tài khoản mẫu khi chạy ứng dụng lần đầu.
    @Override
    public void run(String... args) {
        if (users.findByUserName("admin").isEmpty()) {
            users.createUser("admin", encoder.encode("123456"));
        }
    }

    public String login(String userName, String encodedPassword) {
        if (userName == null || userName.isBlank()
                || encodedPassword == null || encodedPassword.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Thieu userName hoac password");
        }

        String password;

        try {
            byte[] bytes = Base64.getDecoder().decode(encodedPassword);
            password = new String(bytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Password khong dung dinh dang Base64");
        }

        // BCrypt giới hạn mật khẩu ở 72 byte.
        if (password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Password qua dai");
        }

        AppUser user = users.findByUserName(userName)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Sai tai khoan hoac mat khau"));

        if (!encoder.matches(password, user.password())) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Sai tai khoan hoac mat khau");
        }

        String token = jwt.createToken(user.userName());

        users.updateToken(user.idUser(), token);

        return token;
    }
}