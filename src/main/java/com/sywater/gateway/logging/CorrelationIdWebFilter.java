package com.sywater.gateway.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.UUID;
import java.util.regex.Pattern;

@Component
@Order(-200)
public class CorrelationIdWebFilter implements WebFilter {

    public static final String HEADER = "X-Correlation-Id";

    private static final Pattern SAFE_ID = Pattern.compile("[A-Za-z0-9-]{1,64}");
    private static final Logger accessLog = LoggerFactory.getLogger("gateway.access");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String incoming = exchange.getRequest().getHeaders().getFirst(HEADER);
        String correlationId = incoming != null && SAFE_ID.matcher(incoming).matches()
                ? incoming
                : UUID.randomUUID().toString();

        ServerHttpRequest request = exchange.getRequest().mutate()
                .headers(headers -> headers.set(HEADER, correlationId))
                .build();
        ServerWebExchange withId = exchange.mutate().request(request).build();
        withId.getResponse().getHeaders().set(HEADER, correlationId);

        long start = System.nanoTime();
        return chain.filter(withId).doFinally(signal -> accessLog.info("{} {} {} -> {} in {} ms",
                correlationId,
                request.getMethod(),
                request.getPath().value(),          // path only: never log the query string or headers
                withId.getResponse().getStatusCode(),
                (System.nanoTime() - start) / 1_000_000));
    }
}