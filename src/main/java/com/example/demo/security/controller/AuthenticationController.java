package com.example.demo.security.controller;


import com.example.demo.security.DTO.AuthenticationRequest;
import com.example.demo.security.DTO.AuthenticationResponse;
import com.example.demo.security.service.AuthenticationService;
import com.example.demo.security.service.CustomUserDetailService;
import com.example.demo.security.service.JwtService;
import com.example.demo.user.SystemUser;
import com.example.demo.user.SystemUserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class AuthenticationController {
    private final JwtService jwtService;
    private final AuthenticationService authenticationService;

    @PostMapping("/authenticate")
    public ResponseEntity<?> verifyAndCreateAuthToken(@RequestBody AuthenticationRequest authenticationRequest){
        try{
            authenticationService.verifyAuthenticationRequest(authenticationRequest);
            return authenticationService.createAuthToken(authenticationRequest);

        }catch (AuthenticationException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Wrong Username or Password");
        }catch (RuntimeException re){
            return ResponseEntity.badRequest().body(String.format("The username %s isn't found", authenticationRequest.getUserName()));
        }
    }

    @GetMapping("/refreshToken")
    public ResponseEntity<?> createAccessTokenFromRefreshToken(HttpServletRequest servletRequest){
        Optional<String> refreshTokenOptional = jwtService.extractJWTFromAuthorizationHeader(servletRequest);
        if (refreshTokenOptional.isEmpty())
            return ResponseEntity.badRequest().body("The refresh token doesn't exist");

        String refreshToken = refreshTokenOptional.get();
        if (jwtService.tokenIsValid(refreshToken)){
            return authenticationService.createAccessTokenFromRefreshToken(refreshToken);
        }
        else
            return ResponseEntity.badRequest().body("The refresh token is invalid");
    }
}
