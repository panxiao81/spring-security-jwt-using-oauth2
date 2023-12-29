package com.example.springbootjwtusingoauth2.application.auth.rest.vo;


import com.example.springbootjwtusingoauth2.application.auth.model.UserEntity;

public record LoginResponse(UserResponse user, String accessToken, String refreshToken) {

    public LoginResponse(UserEntity user, String access, String refresh) {
        this(new UserResponse(user), access, refresh);
    }
}
