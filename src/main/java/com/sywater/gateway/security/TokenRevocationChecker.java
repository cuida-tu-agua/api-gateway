package com.sywater.gateway.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Instant;

@Component
public class TokenRevocationChecker {

    static final String JTI_PREFIX = "iam:revoked:jti:";
    static final String USER_PREFIX = "iam:revoked-before:";

    private static final Logger log = LoggerFactory.getLogger(TokenRevocationChecker.class);

    private final ReactiveStringRedisTemplate redis;

    public TokenRevocationChecker(ReactiveStringRedisTemplate redis) {
        this.redis = redis;
    }

    public Mono<Boolean> isRevoked(Jwt jwt) {
        String tokenId = jwt.getId();
        String userId = jwt.getSubject();
        Instant issuedAt = jwt.getIssuedAt();

        Mono<Boolean> byTokenId = tokenId == null
                ? Mono.just(false)
                : redis.hasKey(JTI_PREFIX + tokenId);

        Mono<Boolean> byUser = (userId == null || issuedAt == null)
                ? Mono.just(false)
                : redis.opsForValue().get(USER_PREFIX + userId)
                .map(before -> issuedAt.getEpochSecond() <= Long.parseLong(before))
                .defaultIfEmpty(false);

        return byTokenId
                .flatMap(revoked -> revoked ? Mono.just(true) : byUser)
                // Redis down: let the request continue; every service checks revocation again
                .onErrorResume(error -> {
                    log.warn("Redis unavailable, revocation not checked at the gateway: {}", error.getMessage());
                    return Mono.just(false);
                });
    }
}