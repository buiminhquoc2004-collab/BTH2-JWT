package com.example.helloapi.repository;

import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.example.helloapi.model.AppUser;

@Repository
public class UserRepository {

    private final JdbcTemplate jdbc;

    public UserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<AppUser> findByUserName(String userName) {
        String sql = """
                SELECT IdUser, UserName, Password, Token
                FROM users
                WHERE UserName = ?
                """;

        return jdbc.query(sql, (rs, rowNum) -> new AppUser(
                rs.getInt("IdUser"),
                rs.getString("UserName"),
                rs.getString("Password"),
                rs.getString("Token")
        ), userName).stream().findFirst();
    }

    public void createUser(String userName, String passwordHash) {
        jdbc.update("""
                INSERT INTO users (UserName, Password)
                VALUES (?, ?)
                """, userName, passwordHash);
    }

    public void updateToken(int idUser, String token) {
        jdbc.update("""
                UPDATE users
                SET Token = ?
                WHERE IdUser = ?
                """, token, idUser);
    }
}