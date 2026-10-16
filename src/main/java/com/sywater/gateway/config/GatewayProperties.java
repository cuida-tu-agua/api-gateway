package com.sywater.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.util.List;

/** The "gateway:" block of application.yml. */
@ConfigurationProperties("gateway")
public record GatewayProperties(Jwt jwt, Cors cors) {

    /** How to verify the tokens issued by ms-iam. */
    public record Jwt(String issuer, Resource publicKey) {}

    /** Origins (scheme + host + port, no trailing slash) allowed to call the gateway from a browser. */
    public record Cors(List<String> allowedOrigins) {}
}   
