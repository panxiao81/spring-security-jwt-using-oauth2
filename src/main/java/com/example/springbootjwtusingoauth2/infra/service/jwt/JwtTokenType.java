package com.example.springbootjwtusingoauth2.infra.service.jwt;

import java.io.Serializable;
import java.util.Objects;

public final class JwtTokenType implements Serializable {
    private final String value;

    public static final JwtTokenType ACCESS_TOKEN = new JwtTokenType("access_token");
    public static final JwtTokenType REFRESH_TOKEN = new JwtTokenType("refresh_token");

    public JwtTokenType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JwtTokenType that = (JwtTokenType) o;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "JwtTokenType{" +
                "value='" + value + '\'' +
                '}';
    }
}
