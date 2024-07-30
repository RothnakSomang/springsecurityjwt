package com.rothnak.springsecurityjwt.controller;

import com.rothnak.springsecurityjwt.auth.AuthenticationRequest;
import com.rothnak.springsecurityjwt.auth.AuthenticationResponse;
import com.rothnak.springsecurityjwt.auth.AuthService;
import com.rothnak.springsecurityjwt.model.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/rothnak/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest registerRequest) {
        //TODO: Register a user and response a jwt token
        AuthenticationResponse authResponse = authService.register(registerRequest);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authService.authenticate(request));
    }
}
