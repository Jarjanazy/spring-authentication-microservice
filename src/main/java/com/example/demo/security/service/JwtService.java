package com.example.demo.security.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

@Service
@Slf4j
public class JwtService {

    private final Algorithm signingAlgorithm;
    private final JWTVerifier verifier;
    private final KeyPair keyPair;

    public JwtService(KeyPair keyPair)
    {
        this.keyPair = keyPair;
        this.signingAlgorithm = Algorithm.RSA256(null, (RSAPrivateKey) keyPair.getPrivate());
        Algorithm verifyingAlgorithm = Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), null);
        this.verifier = JWT.require(verifyingAlgorithm).build();
    }

    public String extractUsername(String token) {
        return verifier.verify(token).getSubject();
    }

    public String createToken(String userName, Optional<Integer> expirationDuration) {

        if (expirationDuration.isPresent())
            return createTokenWithNoExpirationDate(userName)
                    .withExpiresAt(new Date(System.currentTimeMillis() + expirationDuration.get()))
                    .sign(signingAlgorithm);
        else
            return createTokenWithNoExpirationDate(userName)
                    .sign(signingAlgorithm);
    }

    public Optional<DecodedJWT> tokenIsValid(String token) {
        try{
            return Optional.of(verifier.verify(token));
        }catch (SignatureVerificationException e){
            log.error("The jwt is invalid "+ token);
            return Optional.empty();
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
            .withIssuedAt(new Date(System.currentTimeMillis()))
            .withClaim("publicKey", getPublicKeyAsString());
    }

    private String getPublicKeyAsString(){
        return Base64
                .getEncoder()
                .encodeToString(keyPair.getPublic().getEncoded());
    }
}
