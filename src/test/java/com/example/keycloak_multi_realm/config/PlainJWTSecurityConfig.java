package com.example.keycloak_multi_realm.config;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

@TestConfiguration
public class PlainJWTSecurityConfig {

    @Bean
    @Primary
    ReactiveAuthenticationManagerResolver issuerResolver(JwtAuthenticationConverter jwtAuthenticationConverter, String[]issuers) {

        final var managers = Arrays.stream(issuers)
                .collect(Collectors.toMap(issuer -> issuer, issuer -> {

                    final var provider = new JwtReactiveAuthenticationManager(plainJwtDecoder());
                    provider.setJwtAuthenticationConverter(new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter));
                    return createManager(provider);
                }));
        return new JwtIssuerReactiveAuthenticationManagerResolver(delegate(managers));
    }

    private ReactiveAuthenticationManager createManager(final JwtReactiveAuthenticationManager provider) {
        return provider::authenticate;
    }
    private ReactiveAuthenticationManagerResolver<String> delegate(Map<String, ReactiveAuthenticationManager> managers) {
        return issuer -> Mono.just(managers.get(issuer));

    }

    @Bean
    @Primary
    public ReactiveJwtDecoder plainJwtDecoder() {
        final WebSecurityJwtConfiguration.UsernameSubClaimAdapter claimAdapter = new WebSecurityJwtConfiguration.UsernameSubClaimAdapter();
        return token -> {
            try {
                final JWT jwt = JWTParser.parse(token);
                final Map<String, Object> claims = claimAdapter.convert(jwt.getJWTClaimsSet().getClaims());
                return Mono.just(Jwt.withTokenValue(token)
                        .headers((h) -> h.putAll(jwt.getHeader().toJSONObject()))
                        .claims((c) -> c.putAll(claims)).build());
            } catch (ParseException e) {
                throw new JwtException(e.getMessage(), e);
            }
        };
    }
}
