package com.example.demo.security.bean;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.io.InputStream;
import java.security.*;

@Configuration
public class CodeItKeyProvider
{
    @Bean
    public KeyPair getKeyPairFromKeyStore() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());

        return generator.generateKeyPair();
    }
}
