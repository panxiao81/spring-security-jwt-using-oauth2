package com.example.springbootjwtusingoauth2.infra.config;

import jakarta.validation.constraints.Min;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@ConfigurationProperties(prefix = "jwt")
@Component
public class JwtProperties {
    @Min(32)
    private String secret = "Please-Change-This-Not-Safety-Key-Please-Please";
    private String issuer;
    /*
    * for minutes, default: 30
    */
    private Long expireTime = 30L;
    private Long refreshExpireTime = 60L;
}
