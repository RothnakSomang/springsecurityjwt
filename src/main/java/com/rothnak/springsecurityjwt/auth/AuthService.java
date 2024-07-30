package com.rothnak.springsecurityjwt.auth;

import com.rothnak.springsecurityjwt.config.JwtService;
import com.rothnak.springsecurityjwt.model.RegisterRequest;
import com.rothnak.springsecurityjwt.model.UserInfm;
import com.rothnak.springsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    //TODO: Save User Info to DB and response the Twt token
    public AuthenticationResponse register(RegisterRequest registerRequest) {
        var user = UserInfm.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                //.username(registerRequest.getUsername())
                .role(registerRequest.getRole())
                .build();
        //1.Save user info to DB
        var savedUser = userRepository.save(user);

        //2.Response Jwt token
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        //FirstStep
            //We need to validate our request (validate whether password & username is correct)
            //Verify whether user present in the database
            //Which AuthenticationProvider -> DaoAuthenticationProvider (Inject)
            //We need to authenticate using authenticationManager injecting this authenticationProvider
        //SecondStep
            //Verify whether userName and password is correct => UserNamePasswordAuthenticationToken
            //Verify whether user present in db
            //generateToken
            //Return the token
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        System.out.println("User: "+ user);
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).build();

    }

}
