package com.example.springbootjwtusingoauth2.infra.service.jwt;

import org.springframework.security.oauth2.core.OAuth2Token;

public interface OAuth2TokenGenerator<T extends OAuth2Token> {
    T generate(JwtTokenContext context);
}
