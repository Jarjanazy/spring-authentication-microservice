package com.example.demo.security;

import com.example.demo.security.service.CustomUserDetailService;
import com.example.demo.security.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

@RequiredArgsConstructor
@Component @Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {

    private final CustomUserDetailService customUserDetailsService;
    private final JwtService jwtService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        setAuthenticationBasedOnJWT(request);

        chain.doFilter(request, response);
    }

    private void setAuthenticationBasedOnJWT(HttpServletRequest request)
    {
        final String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer "))
            return;

        String jwt = authorizationHeader.substring(7);

        String username = jwtService.extractUsername(jwt);

        UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(username);

        if (jwtService.tokenIsValid(jwt, userDetails))
            setAuthenticationInSecurityContext(request, userDetails);
    }

    private void setAuthenticationInSecurityContext(HttpServletRequest request, UserDetails userDetails) {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }

}
