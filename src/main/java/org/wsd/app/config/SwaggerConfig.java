package org.wsd.app.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.extensions.Extension;
import io.swagger.v3.oas.annotations.extensions.Extensions;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@OpenAPIDefinition(
        info = @Info(title = "Resource Server", description = "", version = "v1")
)
@SecurityScheme(
        name = "security_oauth",
        type = SecuritySchemeType.OAUTH2,
        flows = @OAuthFlows(
                authorizationCode = @OAuthFlow(
                        authorizationUrl = "http://localhost:9000/oauth2/authorize",
                        tokenUrl = "http://localhost:9000/oauth2/token",
                        scopes = {
                                @OAuthScope(name = "openid", description = "openid description"),
                                @OAuthScope(name = "profile", description = "openid description"),
                                @OAuthScope(name = "read", description = "openid description"),
                        }
                )
        )
)
@PropertySource("classpath:swagger/swagger.properties")
public class SwaggerConfig {

}
