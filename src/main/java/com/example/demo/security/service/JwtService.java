package com.example.demo.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

@Service
public class JwtService {

    private final String SECRET_KEY = "secret";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Optional<Date> extractExpiration(String token) {
        return Optional.ofNullable(extractClaim(token, Claims::getExpiration));
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails, Optional<Integer> expirationDuration) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername(), expirationDuration);
    }

    public Boolean tokenIsValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token)
                .map(date -> date.before(new Date()))
                .orElse(false);
    }

    private String createToken(Map<String, Object> claims, String subject, Optional<Integer> expirationDuration) {
        if (expirationDuration.isPresent())
            return createTokenWithNoExpirationDate(claims, subject)
                    .setExpiration(new Date(System.currentTimeMillis() + expirationDuration.get()))
                    .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
        else
            return createTokenWithNoExpirationDate(claims, subject)
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
    }

    private JwtBuilder createTokenWithNoExpirationDate(Map<String, Object> claims, String subject)
    {
        return Jwts
                .builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()));
    }
}
