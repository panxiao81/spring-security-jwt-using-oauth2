package com.example.springbootjwtusingoauth2.application.config;

import com.example.springbootjwtusingoauth2.application.auth.model.UserEntity;
import com.example.springbootjwtusingoauth2.infra.config.JwtProperties;
import com.example.springbootjwtusingoauth2.application.auth.model.UserEntityRepository;
import com.example.springbootjwtusingoauth2.infra.security.JpaUserDetailsManager;
import com.example.springbootjwtusingoauth2.infra.service.jwt.JwtAccessTokenGenerator;
import com.example.springbootjwtusingoauth2.infra.service.jwt.JwtDelegatingTokenGenerator;
import com.example.springbootjwtusingoauth2.infra.service.jwt.JwtRefreshTokenGenerator;
import com.example.springbootjwtusingoauth2.infra.service.jwt.OAuth2TokenGenerator;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(c -> c
                        .requestMatchers("/login/**").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/register").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(c -> c.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JpaUserDetailsManager<UserEntity> userDetailsService(UserEntityRepository userEntityRepository) {
        return new JpaUserDetailsManager<>(userEntityRepository);
    }
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        return daoAuthenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider daoAuthenticationProvider, JwtAuthenticationProvider jwtAuthenticationProvider) {
        return new ProviderManager(daoAuthenticationProvider, jwtAuthenticationProvider);
    }

    @Bean
    public SecretKey jwtSecretKey(JwtProperties jwtProperties) {
        // https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#keygenerator-algorithms
        return new SecretKeySpec(jwtProperties.getSecret().getBytes(), "HmacSHA256");
    }

    @Bean
    public JwtDecoder jwtDecoder(SecretKey key) {
        return NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256)
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(SecretKey key) {
        JWKSource<SecurityContext> secret = new ImmutableSecret<>(key);
        return new NimbusJwtEncoder(secret);
    }

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> jwtTokenGenerator(JwtEncoder jwtEncoder, JwtProperties jwtProperties) {
        JwtAccessTokenGenerator jwtAccessTokenGenerator = new JwtAccessTokenGenerator(jwtEncoder, jwtProperties);
        JwtRefreshTokenGenerator jwtRefreshTokenGenerator = new JwtRefreshTokenGenerator(jwtEncoder, jwtProperties);
        return new JwtDelegatingTokenGenerator(jwtAccessTokenGenerator, jwtRefreshTokenGenerator);
    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider(JwtDecoder jwtDecoder) {
        return new JwtAuthenticationProvider(jwtDecoder);
    }
}
