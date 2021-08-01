package com.example.demo.security.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.Optional;

@Service @Slf4j
public class JwtService {

    private final String SECRET_KEY = "secret";
    private final Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
    private final JWTVerifier verifier = JWT.require(algorithm).build();


    public String extractUsername(String token) {
        return verifier.verify(token).getSubject();
    }

    public String createToken(String userName, Optional<Integer> expirationDuration) {

        if (expirationDuration.isPresent())
            return createTokenWithNoExpirationDate(userName)
                    .withExpiresAt(new Date(System.currentTimeMillis() + expirationDuration.get()))
                    .sign(algorithm);
        else
            return createTokenWithNoExpirationDate(userName)
                    .sign(algorithm);
    }

    public Boolean tokenIsValid(String token) {
        try{
            verifier.verify(token);
            return true;
        }catch (SignatureVerificationException e){
            log.error("The jwt is invalid "+ token);
            return false;
        }
    }

    public Optional<String> extractJWTFromAuthorizationHeader(HttpServletRequest servletRequest){
        final String authorizationHeader = servletRequest.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer "))
            return Optional.empty();

        return Optional.of(authorizationHeader.substring(7));
    }

    private JWTCreator.Builder createTokenWithNoExpirationDate(String userName)
    {
        return JWT
            .create()
            .withSubject(userName)
            .withIssuedAt(new Date(System.currentTimeMillis()));
    }
}
