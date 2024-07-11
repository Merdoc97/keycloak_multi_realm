package com.example.keycloak_multi_realm.config;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import static com.example.keycloak_multi_realm.config.KeycloakRoleScopeConverter.REALM_ACCESS;
import static com.example.keycloak_multi_realm.config.KeycloakRoleScopeConverter.ROLES;
import static java.util.Collections.singletonMap;

public class JwtHelper {

    private JwtHelper() {
    }

    public static String generateJwt(String name, Set<String> roles, String scope, String issuer) {
        JWTClaimsSet.Builder builder = defaultClaims(name, scope, issuer).claim(REALM_ACCESS, singletonMap(ROLES, roles));
        return "bearer ".concat(new PlainJWT(builder.build()).serialize());
    }

    private static JWTClaimsSet.Builder defaultClaims(String name, String scope, String issuer) {
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(UUID.randomUUID().toString())
                .claim("preferred_username", name)
                .claim("scope", scope)
                .expirationTime(Date.from(ZonedDateTime.now().plusDays(1).toInstant()));
    }
}
