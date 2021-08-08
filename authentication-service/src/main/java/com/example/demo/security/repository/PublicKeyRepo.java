package com.example.demo.security.repository;

import com.example.demo.security.entity.AppPublicKey;
import org.springframework.data.repository.CrudRepository;

public interface PublicKeyRepo extends CrudRepository<AppPublicKey, Integer>
{
}
