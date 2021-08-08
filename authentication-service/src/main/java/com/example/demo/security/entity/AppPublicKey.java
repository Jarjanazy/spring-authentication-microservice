package com.example.demo.security.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Date;

@Entity @Builder @NoArgsConstructor @Data @AllArgsConstructor
public class AppPublicKey
{
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Integer id;

    @Column(nullable = false, name = "public_key")
    private String publicKey;

    @Column(nullable = false, name = "creation_date")
    private Date creationDate;
}
