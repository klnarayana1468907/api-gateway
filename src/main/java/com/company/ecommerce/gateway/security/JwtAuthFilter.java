package com.company.ecommerce.gateway.security;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();

        // 🔓 Public APIs
        if (path.startsWith("/api/auth/") || path.startsWith("/api/internal/users")) {
            return chain.filter(exchange);
        }
        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        // ❌ Missing token
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return writeError(
                    exchange,
                    HttpStatus.UNAUTHORIZED,
                    "Missing or invalid Authorization header"
            );
        }

        try {
            String token = authHeader.substring(7);
            Claims claims = jwtUtil.extractClaims(token);

            String role = claims.get("role", String.class);
            String userId = String.valueOf(claims.get("userId"));


            // ❌ Role missing
            if (role == null) {
                return writeError(
                        exchange,
                        HttpStatus.UNAUTHORIZED,
                        "Invalid token: role missing"
                );
            }

            // USER APIs → USER role only
            if (path.startsWith("/api/users")
                    && !"USER".equalsIgnoreCase(role)) {

                return writeError(
                        exchange,
                        HttpStatus.FORBIDDEN,
                        "USER role required"
                );
            }

            // ✅ Forward user info
            exchange = exchange.mutate()
                    .request(r -> r
                    		.header("X-User-Id", userId)
                            .header("X-User-Email", claims.getSubject())
                            .header("X-User-Role", role))
                    .build();

        } catch (Exception e) {
            // ❌ Invalid / expired JWT
            return writeError(
                    exchange,
                    HttpStatus.UNAUTHORIZED,
                    "Invalid or expired JWT token"
            );
        }

        return chain.filter(exchange);
    }

    // ✅ SAFE error writer (NO Mono.error)
    private Mono<Void> writeError(ServerWebExchange exchange,
                                 HttpStatus status,
                                 String message) {

        String body = String.format(
                "{\"status\":%d,\"error\":\"%s\",\"message\":\"%s\",\"path\":\"%s\"}",
                status.value(),
                status.getReasonPhrase(),
                message,
                exchange.getRequest().getPath().value()
        );

        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders()
                .setContentType(MediaType.APPLICATION_JSON);

        return exchange.getResponse().writeWith(
                Mono.just(
                        exchange.getResponse()
                                .bufferFactory()
                                .wrap(body.getBytes())
                )
        );
    }

    @Override
    public int getOrder() {
        return -1; // run BEFORE routing
    }
}
