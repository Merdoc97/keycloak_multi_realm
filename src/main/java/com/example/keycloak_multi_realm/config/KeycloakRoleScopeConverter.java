package com.example.keycloak_multi_realm.config;

import jakarta.annotation.Nullable;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

final class KeycloakRoleScopeConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    public static final String REALM_ACCESS = "realm_access";
    public static final String ROLES = "roles";
    private static final String SCOPE = "scope";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        return Stream.concat(getRoles(jwt), getScopes(jwt))
                .collect(Collectors.toList());
    }

    private Stream<SimpleGrantedAuthority> getRoles(Jwt jwt) {
        return Optional.ofNullable(jwt)
                .map(j -> castIfPresent(j.getClaim(REALM_ACCESS), Map.class))
                .map(cl -> castIfPresent(cl.get(ROLES), List.class))
                .map(list -> list.stream()
                        .map(s -> new SimpleGrantedAuthority("ROLE_" + (String) s)))
                .orElse(Stream.empty());
    }

    @Nullable
    private <T> T castIfPresent(final Object object, final Class<T> expectedClass) {
        if (expectedClass.isInstance(object)) {
            return expectedClass.cast(object);
        }
        return null;
    }

    private Stream<SimpleGrantedAuthority> getScopes(Jwt jwt) {
        return Optional.ofNullable(jwt.getClaims())
                .filter(claims -> claims.containsKey(SCOPE))
                .map(claim -> claim.get(SCOPE))
                .map(Object::toString)
                .stream()
                .flatMap(scope -> Arrays.stream(scope.split(" ")))
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope));
    }
}
