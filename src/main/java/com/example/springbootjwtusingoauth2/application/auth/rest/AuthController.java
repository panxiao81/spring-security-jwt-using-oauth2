package com.example.springbootjwtusingoauth2.application.auth.rest;

import com.example.springbootjwtusingoauth2.application.auth.model.UserEntity;
import com.example.springbootjwtusingoauth2.application.auth.rest.vo.LoginRequest;
import com.example.springbootjwtusingoauth2.application.auth.rest.vo.LoginResponse;
import com.example.springbootjwtusingoauth2.application.auth.rest.vo.RegisterRequest;
import com.example.springbootjwtusingoauth2.application.auth.rest.vo.RegisterResponse;
import com.example.springbootjwtusingoauth2.application.auth.service.AuthService;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        LoginResponse response = authService.login(loginRequest);
        return ResponseEntity.status(HttpStatusCode.valueOf(200))
                .body(response);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest) {
        UserEntity user = authService.register(registerRequest);
        return ResponseEntity.status(HttpStatusCode.valueOf(201)).body(
                new RegisterResponse(user)
        );
    }

    @GetMapping("/user/me")
    public ResponseEntity<?> me(@AuthenticationPrincipal Jwt principal) {
        return ResponseEntity.ok(principal);
    }
}
