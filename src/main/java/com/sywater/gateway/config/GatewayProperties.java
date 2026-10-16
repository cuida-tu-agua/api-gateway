package com.sywater.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.util.List;

@ConfigurationProperties("gateway")
public record GatewayProperties(Jwt jwt, Cors cors) {

    public record Jwt(String issuer, Resource publicKey) {}

    public record Cors(List<String> allowedOrigins) {}
}
