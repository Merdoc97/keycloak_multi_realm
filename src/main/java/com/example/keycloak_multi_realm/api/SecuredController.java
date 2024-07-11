package com.example.keycloak_multi_realm.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api")
@Slf4j
class SecuredController {

    @GetMapping("/hello")
    @PreAuthorize("isFullyAuthenticated()")
    Mono<String> hello(JwtAuthenticationToken authenticationToken) {
        log.info("Authorization {}", authenticationToken);
        return Mono.just(("Hello"));
    }

    @GetMapping("/role")
    @PreAuthorize("hasRole('user_role')")
    Mono<ResponseEntity<String>> roleProtectedEndpoint(JwtAuthenticationToken authenticationToken) {
        log.info("Authorization {}", authenticationToken);
        return Mono.just(ResponseEntity.ok("Hello role"));
    }

    @GetMapping("/scope")
    @PreAuthorize("hasAuthority('SCOPE_some-scope')")
    Mono<ResponseEntity<String>> scopeProtectedEndpoint(JwtAuthenticationToken authenticationToken) {
        log.info("Authorization {}", authenticationToken);
        return Mono.just(ResponseEntity.ok("Hello scope"));
    }
}
