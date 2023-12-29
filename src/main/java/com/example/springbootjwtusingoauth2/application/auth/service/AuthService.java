package com.example.springbootjwtusingoauth2.application.auth.service;

import com.example.springbootjwtusingoauth2.application.auth.model.UserEntity;
import com.example.springbootjwtusingoauth2.application.auth.rest.vo.LoginRequest;
import com.example.springbootjwtusingoauth2.application.auth.rest.vo.LoginResponse;
import com.example.springbootjwtusingoauth2.application.auth.rest.vo.RegisterRequest;
import com.example.springbootjwtusingoauth2.infra.security.JpaUserDetailsManager;
import com.example.springbootjwtusingoauth2.infra.service.jwt.JwtTokenContext;
import com.example.springbootjwtusingoauth2.infra.service.jwt.JwtTokenType;
import com.example.springbootjwtusingoauth2.infra.service.jwt.OAuth2TokenGenerator;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuthService {
    private final JpaUserDetailsManager<UserEntity> jpaUserDetailsManager;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final OAuth2TokenGenerator<?> OAuth2TokenGenerator;

    public AuthService(JpaUserDetailsManager<UserEntity> jpaUserDetailsManager, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, OAuth2TokenGenerator<?> OAuth2TokenGenerator) {
        this.jpaUserDetailsManager = jpaUserDetailsManager;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.OAuth2TokenGenerator = OAuth2TokenGenerator;
    }

    public LoginResponse login(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password())
        );
        UserEntity user = (UserEntity) authentication.getPrincipal();

        JwtTokenContext access = JwtTokenContext.builder()
                .type(JwtTokenType.ACCESS_TOKEN)
                .claims(Map.of(
                        "authorities", user.getAuthorities()
                ))
                .authentication(authentication)
                .build();
        JwtTokenContext refresh = JwtTokenContext.builder()
                .type(JwtTokenType.REFRESH_TOKEN)
                .authentication(authentication)
                .build();

        return new LoginResponse(user, OAuth2TokenGenerator.generate(access).getTokenValue(), OAuth2TokenGenerator.generate(refresh).getTokenValue());
    }

    public UserEntity register(RegisterRequest registerRequest) {
        UserEntity user = (UserEntity) UserEntity.builder()
                        .username(registerRequest.username())
                        .password(registerRequest.password())
                                .passwordEncoder(passwordEncoder::encode)
                                        .build();
        jpaUserDetailsManager.createUser(user);
        return user;
    }
}
