package com.example.keycloak_multi_realm.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@Slf4j
class SecuredController {

    @GetMapping("/hello")
    @PreAuthorize("isFullyAuthenticated()")
    ResponseEntity<String> hello(JwtAuthenticationToken authenticationToken) {
        log.info("Authorization {}", authenticationToken);
        return ResponseEntity.ok("Hello");
    }

    @GetMapping("/role")
    @PreAuthorize("hasRole('user_role')")
    ResponseEntity<String> roleProtectedEndpoint(JwtAuthenticationToken authenticationToken) {
        log.info("Authorization {}", authenticationToken);
        return ResponseEntity.ok("Hello role");
    }

    @GetMapping("/scope")
    @PreAuthorize("hasAuthority('SCOPE_some-scope')")
    ResponseEntity<String> scopeProtectedEndpoint(JwtAuthenticationToken authenticationToken) {
        log.info("Authorization {}", authenticationToken);
        return ResponseEntity.ok("Hello scope");
    }
}
