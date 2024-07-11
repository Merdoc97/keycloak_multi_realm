package com.example.keycloak_multi_realm.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class WebSecurityJwtConfiguration {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuers-uri}")
    private String[] issuers;

    @Bean
    SecurityWebFilterChain configure(final ServerHttpSecurity http, final ReactiveAuthenticationManagerResolver issuerResolver) throws Exception {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .anonymous(ServerHttpSecurity.AnonymousSpec::disable)
                .oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(issuerResolver))
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.anyExchange().authenticated());
        return http.build();

    }

    @Bean
    @ConditionalOnMissingBean
    ReactiveAuthenticationManagerResolver issuerResolver(JwtAuthenticationConverter jwtAuthenticationConverter, String[] issuers) {
        final var managers = Arrays.stream(issuers)
                .collect(Collectors.toMap(issuer -> issuer, issuer -> {
                    final NimbusReactiveJwtDecoder decoder = (NimbusReactiveJwtDecoder) ReactiveJwtDecoders.fromIssuerLocation(issuer);
                    decoder.setClaimSetConverter(new UsernameSubClaimAdapter());
                    var provider = new JwtReactiveAuthenticationManager(decoder);
                    provider.setJwtAuthenticationConverter(new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter));
                    return createManager(provider);
                }));

        return new JwtIssuerReactiveAuthenticationManagerResolver(delegate(managers));

    }

    private ReactiveAuthenticationManagerResolver<String> delegate(Map<String, ReactiveAuthenticationManager> managers) {
        return issuer -> Mono.just(managers.get(issuer));

    }

    private ReactiveAuthenticationManager createManager(final JwtReactiveAuthenticationManager provider) {
        return provider::authenticate;
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        final var converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleScopeConverter());
        return converter;
    }

    public static class UsernameSubClaimAdapter implements Converter<Map<String, Object>, Map<String, Object>> {
        private final MappedJwtClaimSetConverter delegate = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

        @Override
        public Map<String, Object> convert(Map<String, Object> claims) {
            final var convertedClaims = this.delegate.convert(claims);
            final var username = (String) convertedClaims.get("preferred_username");
            convertedClaims.put("sub", username);
            return convertedClaims;
        }
    }

    @Bean
    String[] issuers() {
        return issuers;
    }
}
