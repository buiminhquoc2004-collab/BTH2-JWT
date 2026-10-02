package com.example.helloapi.security;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;

import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

@Service
public class JwtService {

    private final Algorithm algorithm;
    private final JWTVerifier verifier;

    public JwtService() {
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        algorithm = Algorithm.HMAC256(secret);

        verifier = JWT.require(algorithm)
                .withIssuer("helloapi")
                .build();
    }

    public String createToken(String userName) {
        Instant now = Instant.now();

        return JWT.create()
                .withIssuer("helloapi")
                .withSubject(userName)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusSeconds(3600)))
                .sign(algorithm);
    }

    public DecodedJWT verifyToken(String token) {
        return verifier.verify(token);
    }
}