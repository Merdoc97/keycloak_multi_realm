package com.example.keycloak_multi_realm.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class WebSecurityJwtConfiguration {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuers-uri}")
    private String[] issuers;

    @Bean
    SecurityFilterChain configure(final HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .anonymous()
                .and()
                .authorizeHttpRequests((auth) -> auth
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .authenticationManagerResolver(issuerResolver()));

        return http.build();
    }

    JwtIssuerAuthenticationManagerResolver issuerResolver() {
        var managers = Arrays.stream(issuers)
                .collect(Collectors.toMap(issuer -> issuer, issuer -> {
                    NimbusJwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuer);
                    decoder.setClaimSetConverter(new UsernameSubClaimAdapter());
                    JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
                    provider.setJwtAuthenticationConverter(jwtAuthenticationConverter());
                    return createManager(provider);
                }));
        return new JwtIssuerAuthenticationManagerResolver(managers::get);
    }

    private AuthenticationManager createManager(final JwtAuthenticationProvider provider) {
        return provider::authenticate;
    }

    JwtAuthenticationConverter jwtAuthenticationConverter() {
        final var converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleScopeConverter());
        return converter;
    }

    private static class UsernameSubClaimAdapter implements Converter<Map<String, Object>, Map<String, Object>> {
        private final MappedJwtClaimSetConverter delegate = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

        @Override
        public Map<String, Object> convert(Map<String, Object> claims) {
            final var convertedClaims = this.delegate.convert(claims);
            final var username = (String) convertedClaims.get("preferred_username");
            convertedClaims.put("sub", username);
            return convertedClaims;
        }
    }
}
