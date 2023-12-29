package com.example.springbootjwtusingoauth2.application.auth.rest.vo;

import com.example.springbootjwtusingoauth2.application.auth.model.UserEntity;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public record UserResponse(Long id, String username, Collection<GrantedAuthority> authority) {
    public UserResponse(UserEntity user) {
        this(user.getId(), user.getUsername(), user.getAuthorities());
    }
}
