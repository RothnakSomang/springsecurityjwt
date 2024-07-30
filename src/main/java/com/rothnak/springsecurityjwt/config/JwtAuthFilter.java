package com.rothnak.springsecurityjwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal
            (@NonNull HttpServletRequest request,
             @NonNull HttpServletResponse response,
             @NonNull FilterChain filterChain)
            throws ServletException, IOException {
            //Verify whether request has Authorization header and it has Bearer in it
            final String authorizationHeader = request.getHeader("Authorization");
            String jwt;
            String email;

            if(authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                filterChain.doFilter(request, response);
                return;
            }

            // Extract jwt from the Authorization
            jwt = authorizationHeader.substring(7);

            email = jwtService.extractUsername(jwt);



            //If user is present and no authentication object in securityContext
            if(email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(email);
                //If valid set to security context holder
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authToken);

            }

        filterChain.doFilter(request, response);
    }

    //TODO:  Verify if it is whitelisted path and if yes dont do anything
    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) throws ServletException {
        return request.getServletPath().contains("/rothnak/v1/auth");
    }
}
