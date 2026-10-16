package com.sywater.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    static final String[] PUBLIC_AUTH_POSTS = {
            "/iam/api/auth/register", "/iam/api/auth/verify-email", "/iam/api/auth/verify-email/resend",
            "/iam/api/auth/login", "/iam/api/auth/refresh",
            "/iam/api/auth/password/forgot", "/iam/api/auth/password/reset",
    };

    static final String[] BLOCKED = {"/*/internal/**", "/*/actuator/**", "/*/health"};

    /** OpenAPI documents of the services, read by the shared Swagger UI (only published where infra enables them). */
    static final String[] OPENAPI_DOCS = {"/*/openapi/**", "/iam/v3/api-docs", "/iam/v3/api-docs/**"};

    static final String[] ADMIN_ONLY = {"/iam/api/admin/**", "/places/api/admin/**", "/devices/api/admin/**"};

    @Bean
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http, ReactiveJwtDecoder jwtDecoder) {
        ServerAuthenticationEntryPoint unauthorized = (exchange, ex) -> writeProblem(exchange,
                HttpStatus.UNAUTHORIZED, "auth.invalid_token", "The access token is missing, expired or revoked.");
        ServerAccessDeniedHandler forbidden = (exchange, ex) -> writeProblem(exchange,
                HttpStatus.FORBIDDEN, "auth.admin_required", "Only an administrator can do this.");

        return http
                // Stateless API with bearer tokens: no cookies, so no CSRF, no login form, no basic auth
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                // Uses the CorsConfigurationSource bean of CorsConfig (Paso 7)
                .cors(Customizer.withDefaults())
                .authorizeExchange(auth -> auth
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()                 // CORS preflight
                        .pathMatchers("/actuator/health").permitAll()                 // gateway health
                        .pathMatchers(BLOCKED).permitAll()                            // → 404 route
                        .pathMatchers(HttpMethod.POST, PUBLIC_AUTH_POSTS).permitAll()
                        .pathMatchers(HttpMethod.GET, "/iam/api/avatars/**").permitAll()
                        .pathMatchers(HttpMethod.GET, OPENAPI_DOCS).permitAll()
                        .pathMatchers(ADMIN_ONLY).hasRole("ADMIN")
                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt
                                .jwtDecoder(jwtDecoder)
                                .jwtAuthenticationConverter(rolesFromToken()))
                        .authenticationEntryPoint(unauthorized)
                        .accessDeniedHandler(forbidden))
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint(unauthorized)
                        .accessDeniedHandler(forbidden))
                .build();
    }

    static Converter<Jwt, Mono<AbstractAuthenticationToken>> rolesFromToken() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<String> roles = jwt.getClaimAsStringList("roles");
            if (roles == null) return List.of();
            return roles.stream()
                    .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();
        });
        converter.setPrincipalClaimName("sub");
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }

    static Mono<Void> writeProblem(ServerWebExchange exchange, HttpStatus status, String title, String detail) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        String body = "{\"type\":\"about:blank\",\"title\":\"" + title + "\",\"status\":" + status.value()
                + ",\"detail\":\"" + detail + "\"}";
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}
