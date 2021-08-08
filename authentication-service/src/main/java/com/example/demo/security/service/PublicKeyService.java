package com.example.demo.security.service;

import com.example.demo.security.repository.PublicKeyRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service @RequiredArgsConstructor
public class PublicKeyService
{
    private final PublicKeyRepo publicKeyRepo;

    public String getPublicKey(){
        return publicKeyRepo
                .findAll()
                .iterator()
                .next()
                .getPublicKey();
    }
}
