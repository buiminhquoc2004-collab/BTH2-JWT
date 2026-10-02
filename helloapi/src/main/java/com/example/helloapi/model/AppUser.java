package com.example.helloapi.model;

public record AppUser(
        int idUser,
        String userName,
        String password,
        String token) {
}