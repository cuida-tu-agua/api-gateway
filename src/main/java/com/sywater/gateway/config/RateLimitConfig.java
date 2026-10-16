package com.sywater.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.security.Principal;

@Configuration
public class RateLimitConfig {

    @Bean
    @Primary
    RedisRateLimiter apiRateLimiter() {
        return new RedisRateLimiter(20, 40, 1);
    }

    @Bean
    RedisRateLimiter authRateLimiter() {
        return new RedisRateLimiter(1, 60, 6);
    }

    @Bean
    @Primary
    KeyResolver userKeyResolver() {
        return exchange -> exchange.getPrincipal()
                .map(Principal::getName)
                .map(userId -> "user:" + userId)
                .switchIfEmpty(Mono.fromSupplier(() -> "ip:" + clientIp(exchange)));
    }

    @Bean
    KeyResolver ipKeyResolver() {
        return exchange -> Mono.just("ip:" + clientIp(exchange));
    }

    static String clientIp(ServerWebExchange exchange) {
        InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
        return remote == null || remote.getAddress() == null ? "unknown" : remote.getAddress().getHostAddress();
    }
}