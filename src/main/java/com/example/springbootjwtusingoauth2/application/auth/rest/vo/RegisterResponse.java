package com.example.springbootjwtusingoauth2.application.auth.rest.vo;

import com.example.springbootjwtusingoauth2.application.auth.model.UserEntity;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;

public record RegisterResponse(Long id, String username, Boolean enabled, Set<GrantedAuthority> authorities) {
    public RegisterResponse(UserEntity userEntity) {
        this(userEntity.getId(), userEntity.getUsername(), userEntity.isEnabled(), userEntity.getAuthorities());
    }
}
