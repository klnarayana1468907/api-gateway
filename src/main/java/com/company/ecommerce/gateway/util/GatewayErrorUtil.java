package com.company.ecommerce.gateway.util;

import com.company.ecommerce.gateway.dto.GatewayErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

public class GatewayErrorUtil {

    private static final ObjectMapper mapper = new ObjectMapper();

    public static Mono<Void> writeError(
            ServerWebExchange exchange,
            HttpStatus status,
            String message) {

        GatewayErrorResponse error = new GatewayErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                message,
                exchange.getRequest().getPath().value()
        );

        byte[] bytes;
        try {
            bytes = mapper.writeValueAsBytes(error);
        } catch (Exception e) {
            return Mono.error(e);
        }

        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders()
                .setContentType(MediaType.APPLICATION_JSON);

        return exchange.getResponse()
                .writeWith(Mono.just(
                        exchange.getResponse()
                                .bufferFactory()
                                .wrap(bytes)
                ));
    }
}
