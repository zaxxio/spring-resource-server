package org.wsd.app.controller;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "Hello Controller")
@SecurityRequirement(name = "security_oauth")
public class HelloController {

    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String sayHelloToUser(@AuthenticationPrincipal Jwt jwt) {
        return "Hello " + jwt.getSubject();
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String sayHelloAdmin(@AuthenticationPrincipal Jwt jwt) {
        return "Hello " + jwt.getSubject();
    }


}
