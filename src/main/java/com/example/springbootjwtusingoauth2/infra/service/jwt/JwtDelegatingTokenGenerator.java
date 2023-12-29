package com.example.springbootjwtusingoauth2.infra.service.jwt;

import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class JwtDelegatingTokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {
    private final List<OAuth2TokenGenerator<OAuth2Token>> tokenGenerators;
    @SafeVarargs
    public JwtDelegatingTokenGenerator(OAuth2TokenGenerator<? extends OAuth2Token>... OAuth2TokenGenerators) {
        Assert.notEmpty(OAuth2TokenGenerators, "jwtTokenGenerators cannot be empty");
        Assert.noNullElements(OAuth2TokenGenerators, "jwtTokenGenerator cannot be null");
        this.tokenGenerators = Collections.unmodifiableList(asList(OAuth2TokenGenerators));
    }

    @SuppressWarnings("unchecked")
    private static List<OAuth2TokenGenerator<OAuth2Token>> asList(OAuth2TokenGenerator<? extends OAuth2Token>... oAuth2TokenGenerators) {
        List<OAuth2TokenGenerator<OAuth2Token>> list = new ArrayList<>();

        for (OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator : oAuth2TokenGenerators) {
            list.add((OAuth2TokenGenerator<OAuth2Token>) oAuth2TokenGenerator);
        }

        return list;
    }

    @Override
    public OAuth2Token generate(JwtTokenContext context) {
        for (OAuth2TokenGenerator<OAuth2Token> tokenGenerator : tokenGenerators) {
            OAuth2Token token = tokenGenerator.generate(context);
            if (token != null) {
                return token;
            }
        }
        return null;
    }
}
