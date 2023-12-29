package com.example.springbootjwtusingoauth2.infra.service.jwt;

import com.example.springbootjwtusingoauth2.infra.config.JwtProperties;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

public class JwtAccessTokenGenerator implements OAuth2TokenGenerator<Jwt> {
    private final JwtEncoder jwtEncoder;
    private final JwtProperties jwtProperties;

    public JwtAccessTokenGenerator(JwtEncoder jwtEncoder, JwtProperties jwtProperties) {
        this.jwtEncoder = jwtEncoder;
        this.jwtProperties = jwtProperties;
    }

    @Override
    public Jwt generate(JwtTokenContext context) {
        if (context.getType() == null ||
            !context.getType().equals(JwtTokenType.ACCESS_TOKEN)) {
            return null;
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(jwtProperties.getExpireTime(), ChronoUnit.MINUTES);

        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
        if (StringUtils.hasText(jwtProperties.getIssuer())) {
            claimsBuilder.issuer(jwtProperties.getIssuer());
        }

        claimsBuilder
                .subject(context.getAuthentication().getName())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .notBefore(issuedAt)
                .claims((map) -> map.putAll(context.getClaims()));

        // TODO: Properties
        JwsAlgorithm jwsAlgorithm = MacAlgorithm.HS256;
        JwsHeader.Builder jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm);


        return this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeaderBuilder.build(), claimsBuilder.build()));
    }
}
