package com.sywater.gateway.security;

import com.sywater.gateway.config.GatewayProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.InputStream;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class JwtConfig {

    @Bean
    ReactiveJwtDecoder jwtDecoder(GatewayProperties properties, TokenRevocationChecker revocations) throws IOException {
        RSAPublicKey publicKey;
        try (InputStream pem = properties.jwt().publicKey().getInputStream()) {
            publicKey = RsaKeyConverters.x509().convert(pem);   // "-----BEGIN PUBLIC KEY-----" (X.509)
        }

        NimbusReactiveJwtDecoder signatureAndClaims = NimbusReactiveJwtDecoder.withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        // Default validators (exp / nbf with 60 s clock skew) + the issuer of ms-iam
        signatureAndClaims.setJwtValidator(JwtValidators.createDefaultWithIssuer(properties.jwt().issuer()));

        // Signature, dates and issuer first; then the revoked list in Redis
        return token -> signatureAndClaims.decode(token)
                .flatMap(jwt -> revocations.isRevoked(jwt)
                        .flatMap(revoked -> revoked
                                ? Mono.error(new BadJwtException("The token was revoked"))
                                : Mono.just(jwt)));
    }
}