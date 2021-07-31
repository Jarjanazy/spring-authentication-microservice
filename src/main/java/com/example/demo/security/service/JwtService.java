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

    public String createToken(String userName, Optional<Integer> expirationDuration) {
        if (expirationDuration.isPresent())
            return createTokenWithNoExpirationDate(userName)
                    .setExpiration(new Date(System.currentTimeMillis() + expirationDuration.get()))
                    .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                    .compact();
        else
            return createTokenWithNoExpirationDate(userName)
                    .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                    .compact();
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

    private JwtBuilder createTokenWithNoExpirationDate(String userName)
    {
        // if we want to add data to the JWT, we add it here
        Map<String, Object> claims = new HashMap<>();
        return Jwts
                .builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()));
    }
}
