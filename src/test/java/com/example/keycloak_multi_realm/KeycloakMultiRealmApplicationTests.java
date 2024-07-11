package com.example.keycloak_multi_realm;

import com.example.keycloak_multi_realm.config.JwtHelper;
import com.example.keycloak_multi_realm.config.PlainJWTSecurityConfig;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@Import(PlainJWTSecurityConfig.class)
@AutoConfigureMockMvc
class KeycloakMultiRealmApplicationTests {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private String[] issuers;

    @Test
    @SneakyThrows
    void testFullyAuthenticated() {
        mockMvc.perform(get("/api/hello")
                        .header("Authorization", JwtHelper.generateJwt("admin", Set.of("admin"), "openid", issuers[0])))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value("Hello"));
    }

    @Test
    @SneakyThrows
    void testFullyAuthenticatedWithoutHeader() {
        mockMvc.perform(get("/api/hello"))
                .andDo(print())
                .andExpect(status().isUnauthorized());
    }
    @Test
    @SneakyThrows
    void testRoleProtectedEndpoint() {
        mockMvc.perform(get("/api/role")
                        .header("Authorization", JwtHelper.generateJwt("user", Set.of("user_role"), "openid", issuers[1])))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value("Hello role"));
    }

    @Test
    @SneakyThrows
    void testRoleProtectedEndpointWrongRole() {
        mockMvc.perform(get("/api/role")
                        .header("Authorization", JwtHelper.generateJwt("user", Set.of("wrong_role"), "openid", issuers[1])))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    @SneakyThrows
    void testRoleProtectedEndpointWithoutToken() {
        mockMvc.perform(get("/api/role"))
                .andDo(print())
                .andExpect(status().isUnauthorized());
    }

    @Test
    @SneakyThrows
    void testScopeProtectedEndpoint() {
        mockMvc.perform(get("/api/scope")
                        .header("Authorization", JwtHelper.generateJwt("user", Set.of("user_role"), "openid some-scope", issuers[1])))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value("Hello scope"));
    }

    @Test
    @SneakyThrows
    void testScopeProtectedEndpointWrongScope() {
        mockMvc.perform(get("/api/scope")
                        .header("Authorization", JwtHelper.generateJwt("user", Set.of("user_role"), "openid", issuers[1])))
                .andDo(print())
                .andExpect(status().isForbidden());
    }
}
