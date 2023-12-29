package com.example.springbootjwtusingoauth2.infra.service.jwt;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Getter
@Builder
public class JwtTokenContext {
    private final JwtTokenType type;
    private final Map<String, Object> claims;
    private final Authentication authentication;

    public JwtTokenContext(JwtTokenType type, Map<String, Object> claims, Authentication authentication) {
        this.type = type;
        this.claims = claims;
        this.authentication = authentication;
    }

    public static class JwtTokenContextBuilder {
        public JwtTokenContext build() {
            Map<JwtTokenType, Function<JwtTokenContextBuilder, Void>> action = new HashMap<>();

            action.put(JwtTokenType.ACCESS_TOKEN, (b) -> {
                Assert.notNull(b.authentication, "Authentication cannot be null");
                if (b.claims == null) {
                    b.claims = new HashMap<>();
                }
                return null;
            });
            action.put(JwtTokenType.REFRESH_TOKEN, (builder) -> {
                Assert.notNull(builder.authentication, "Authentication cannot be null");
                return null;
            });

            action.get(this.type).apply(this);
            return new JwtTokenContext(this.type, this.claims, this.authentication);
        }
    }
}
