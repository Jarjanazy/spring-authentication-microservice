package com.example.demo.security.service;

import com.example.demo.security.DTO.AuthenticationRequest;
import com.example.demo.security.DTO.AuthenticationResponse;
import com.example.demo.user.SystemUser;
import com.example.demo.user.SystemUserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Optional;

@RequiredArgsConstructor
@Service
public class AuthenticationService
{
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailService customUserDetailService;
    private final SystemUserRepo userRepo;
    private final JwtService jwtService;

    public ResponseEntity<AuthenticationResponse> createAccessTokenFromRefreshToken(String refreshToken)
    {
        String userName = jwtService.extractUsername(refreshToken);
        String newAccessToken = createAccessToken(userName);
        return ResponseEntity.ok(new AuthenticationResponse(newAccessToken));
    }

    public ResponseEntity<AuthenticationResponse> createAuthToken(AuthenticationRequest authenticationRequest) {
        UserDetails userDetails =  customUserDetailService.loadUserByUsername(authenticationRequest.getUserName());

        String accessToken = createAccessToken(userDetails.getUsername());
        String refreshToken = jwtService.createToken(userDetails.getUsername(), Optional.empty());

        SystemUser user = userRepo.
                findByUserName(userDetails.getUsername()).
                orElseThrow(() -> new RuntimeException(""));

        return ResponseEntity.ok(new AuthenticationResponse(refreshToken, accessToken, user.getUserName()));
    }
    // if this method runs successfully it means that authentication done successfully
    public void verifyAuthenticationRequest(AuthenticationRequest ar) {
        var authentication = new UsernamePasswordAuthenticationToken(ar.getUserName(), ar.getPassword());
        authenticationManager.authenticate(authentication);
    }

    private String createAccessToken(String userName)
    {
        return jwtService.createToken(userName, Optional.of(1000 * 60));
    }
}
