package com.example.demo.security.service;

import com.example.demo.security.entity.AppPublicKey;
import com.example.demo.security.repository.PublicKeyRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service @RequiredArgsConstructor
public class PublicKeyService
{
    private final PublicKeyRepo publicKeyRepo;

    public String getPublicKey(){
        AppPublicKey appPublicKey = Optional.ofNullable(
                    publicKeyRepo
                    .findAll()
                    .iterator()
                    .next())
                .orElseThrow(RuntimeException::new);
        return appPublicKey.getPublicKey();
    }
}
