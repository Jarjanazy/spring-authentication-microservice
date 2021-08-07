package com.example.demo;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.security.service.JwtService;
import com.example.demo.security.service.RSAService;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class RSATest
{
    @Test
    public void givenASignedMessage_VerifyIt() throws Exception
    {
        KeyPair keyPair = RSAService.generateKeyPair();
        JwtService jwtService = new JwtService(keyPair);

        String token = jwtService.createToken("abdo", Optional.empty());

        Optional<DecodedJWT> decodedJWT = jwtService.tokenIsValid(token);

        assertTrue(decodedJWT.isPresent());
        assertEquals("abdo", decodedJWT.get().getSubject());
        assertNotNull(decodedJWT.get().getClaim("publicKey"));
    }
}
