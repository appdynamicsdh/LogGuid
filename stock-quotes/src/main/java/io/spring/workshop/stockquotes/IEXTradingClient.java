package io.spring.workshop.stockquotes;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * IEXTradingClient fetch stocks data using the "iextrading.com" API
 * For more info see: https://iextrading.com/developer/docs/#stocks
 */
@Component
public class IEXTradingClient {
    private Logger logger = LoggerFactory.getLogger(getClass());

    public Mono<JsonNode> search(LinkedMultiValueMap<String, String> params) {

        return WebClient.create().get()
                .uri(builder -> builder.scheme("https")
                        .host("ws-api.iextrading.com")
                        .path("/1.0/stock/market/batch")
                        .queryParams(params)
                        .build()
                )
                .retrieve().bodyToMono(JsonNode.class);
    }

}
