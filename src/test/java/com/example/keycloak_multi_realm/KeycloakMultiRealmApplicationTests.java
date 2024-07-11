package com.example.keycloak_multi_realm;

import com.example.keycloak_multi_realm.config.JwtHelper;
import com.example.keycloak_multi_realm.config.PlainJWTSecurityConfig;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Set;

@SpringBootTest
@Import(PlainJWTSecurityConfig.class)
@AutoConfigureWebTestClient
class KeycloakMultiRealmApplicationTests {

    @Autowired
    private WebTestClient webTestClient;
    @Autowired
    private String[] issuers;

    @Test
    @SneakyThrows
    void testFullyAuthenticated() {
        webTestClient.get()
                .uri("/api/hello")
                .header("Authorization", JwtHelper.generateJwt("admin", Set.of("admin"), "openid", issuers[0]))
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("Hello");

    }

    @Test
    @SneakyThrows
    void testFullyAuthenticatedWithoutHeader() {
        webTestClient.get()
                .uri("/api/hello")
                .exchange()
                .expectStatus().isUnauthorized();
    }


    @Test
    @SneakyThrows
    void testRoleProtectedEndpoint() {
        webTestClient.get().uri("/api/role")
                .header("Authorization", JwtHelper.generateJwt("user", Set.of("user_role"), "openid", issuers[1]))
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("Hello role");
    }

    @Test
    @SneakyThrows
    void testRoleProtectedEndpointWrongRole() {
        webTestClient.get().uri("/api/role")
                .header("Authorization", JwtHelper.generateJwt("user", Set.of("wrong_role"), "openid", issuers[1]))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    @SneakyThrows
    void testRoleProtectedEndpointWithoutToken() {
        webTestClient.get().uri("/api/role")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    @SneakyThrows
    void testScopeProtectedEndpoint() {
        webTestClient.get().uri("/api/scope")
                .header("Authorization", JwtHelper.generateJwt("user", Set.of("user_role"), "openid some-scope", issuers[1]))
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo(("Hello scope"));
    }

    @Test
    @SneakyThrows
    void testScopeProtectedEndpointWrongScope() {
        webTestClient.get().uri("/api/scope")
                .header("Authorization", JwtHelper.generateJwt("user", Set.of("user_role"), "openid", issuers[1]))
                .exchange()
                .expectStatus().isForbidden();
    }
}
