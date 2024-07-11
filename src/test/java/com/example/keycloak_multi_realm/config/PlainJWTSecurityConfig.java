package com.example.keycloak_multi_realm.config;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

@TestConfiguration
public class PlainJWTSecurityConfig {

    @Bean
    @Primary
    AuthenticationManagerResolver issuerResolver(JwtAuthenticationConverter jwtAuthenticationConverter,String[]issuers) {

        final var managers = Arrays.stream(issuers)
                .collect(Collectors.toMap(issuer -> issuer, issuer -> {

                    final var provider = new JwtAuthenticationProvider(plainJwtDecoder());
                    provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
                    return createManager(provider);
                }));
        return new JwtIssuerAuthenticationManagerResolver(managers::get);
    }

    private AuthenticationManager createManager(final JwtAuthenticationProvider provider) {
        return provider::authenticate;
    }

    @Bean
    @Primary
    public JwtDecoder plainJwtDecoder() {
        final WebSecurityJwtConfiguration.UsernameSubClaimAdapter claimAdapter = new WebSecurityJwtConfiguration.UsernameSubClaimAdapter();
        return token -> {
            try {
                final JWT jwt = JWTParser.parse(token);
                final Map<String, Object> claims = claimAdapter.convert(jwt.getJWTClaimsSet().getClaims());
                return Jwt.withTokenValue(token)
                        .headers((h) -> h.putAll(jwt.getHeader().toJSONObject()))
                        .claims((c) -> c.putAll(claims)).build();
            } catch (ParseException e) {
                throw new JwtException(e.getMessage(), e);
            }
        };
    }
}
