package com.example.demo.security.bean;

import com.example.demo.security.entity.AppPublicKey;
import com.example.demo.security.repository.PublicKeyRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.security.*;
import java.util.Base64;
import java.util.Date;

@Configuration @RequiredArgsConstructor
public class CodeItKeyProvider
{
    private final PublicKeyRepo publicKeyRepo;

    @Bean
    public KeyPair getKeyPairFromKeyStore() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());

        KeyPair keyPair = generator.generateKeyPair();

        AppPublicKey appPublicKey = AppPublicKey
                .builder()
                .publicKey(getPublicKeyAsString(keyPair.getPublic()))
                .creationDate(new Date())
                .build();

        publicKeyRepo.save(appPublicKey);

        return keyPair;
    }

    private String getPublicKeyAsString(PublicKey publicKey){
        return Base64
                .getEncoder()
                .encodeToString(publicKey.getEncoded());
    }
}
