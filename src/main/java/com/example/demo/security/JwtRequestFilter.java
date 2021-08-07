package com.example.demo.security;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.example.demo.security.service.CustomUserDetailService;
import com.example.demo.security.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@RequiredArgsConstructor
@Component @Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {

    private final CustomUserDetailService customUserDetailsService;
    private final JwtService jwtService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        try{
            setAuthenticationBasedOnJWT(request);

            chain.doFilter(request, response);

        }catch (TokenExpiredException e){
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.getWriter().write("The access token has expired");
        }
    }

    private void setAuthenticationBasedOnJWT(HttpServletRequest request)
    {
        Optional<String> jwt = jwtService.extractJWTFromAuthorizationHeader(request);

        if (jwt.isEmpty())
            return;

        String username = jwtService.extractUsername(jwt.get());

        UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(username);

        if (jwtService.tokenIsValid(jwt.get()).isPresent())
            setAuthenticationInSecurityContext(request, userDetails);
    }

    private void setAuthenticationInSecurityContext(HttpServletRequest request, UserDetails userDetails) {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }

}
