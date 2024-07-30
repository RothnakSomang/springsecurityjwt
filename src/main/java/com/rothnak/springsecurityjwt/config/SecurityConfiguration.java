package com.rothnak.springsecurityjwt.config;

import com.rothnak.springsecurityjwt.model.Permission;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


import static com.rothnak.springsecurityjwt.model.Permission.*;
import static com.rothnak.springsecurityjwt.model.Role.ADMIN;
import static com.rothnak.springsecurityjwt.model.Role.MEMBER;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {

    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthFilter jwtAuthFilter;

    //TODO: Allow access for endpoint "/register"
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer:: disable)
                .authorizeHttpRequests(req ->
                        req.requestMatchers("/rothnak/v1/auth/*")
                                .permitAll()
                                .requestMatchers("/rothnak/v1/management/**", "/rothnak/v1/admin/**").hasAnyRole(ADMIN.name(), MEMBER.name())
                                .requestMatchers(GET,"/rothnak/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MEMBER_READ.name())
                                .requestMatchers(GET,"/rothnak/v1/admin/**").hasAnyAuthority(ADMIN_READ.name(), MEMBER_READ.name())
                                .requestMatchers(POST,"/rothnak/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MEMBER_CREATE.name())
                                .anyRequest()
                                .authenticated())
                .sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();

    }
}
