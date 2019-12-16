package io.spring.workshop.stockquotes;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import reactor.core.publisher.Mono;

import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.SignalType;

import java.util.function.Consumer;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_STREAM_JSON;
import static org.springframework.web.reactive.function.server.ServerResponse.ok;

@Component
public class QuoteHandler {

	private Logger logger = LoggerFactory.getLogger(getClass());

	private final QuoteGenerator quoteGenerator;

	@Autowired
    private SearchRequestValidator searchRequestValidator;

	@Autowired
	private IEXTradingClient iexTradingClient;

	@Autowired
	private Google google;

	public QuoteHandler(QuoteGenerator quoteGenerator) {
		this.quoteGenerator = quoteGenerator;
	}

	/**
	 * This method will stream quotes with randomly change prices until the client terminate the request or the
	 * stockquotes service/application is terminated.
	 * @param request - the reactive ServerRequest object
	 * @return - a Mono of ServerResponse streaming JSON
	 */
	public Mono<ServerResponse> streamQuotes(ServerRequest request) {
		return ok()
				.contentType(APPLICATION_STREAM_JSON)
				.body(this.quoteGenerator.fetchQuoteStream(), Quote.class);
	}

	/**
	 * Non-streaming version of this.streamQuotes method.
	 * This method Adds behavior to be triggered after the transaction terminates for any reason, including cancellation.
	 * @param request - the reactive ServerRequest object
	 * @return - a Mono of ServerResponse (non-streaming) JSON per request.
	 */
	public Mono<ServerResponse> fetchQuotes(ServerRequest request) {
		long startTimeMillis = System.currentTimeMillis();
		return ok()
				.contentType(APPLICATION_JSON)
				.body(this.quoteGenerator.fetchQuotesRandom(), Quote.class)
				.doFinally(onTransactionComplete(startTimeMillis));
	}

	/**
	 * @param startTimeMillis - the startTime (in Millis) of the transaction
	 * @return  - a Consumer with the behavior to be triggered after the Mono terminates.
	 */
	private Consumer<SignalType> onTransactionComplete(long startTimeMillis) {
		return signalType -> {
			logger.info(String.format("SignalType=%s",signalType.name()));
            onComplete(System.currentTimeMillis() - startTimeMillis);
        };
	}

	private void onComplete(long elapseTimeMillis) {
		logger.info("transactionElapseTimeMillis="+elapseTimeMillis);
	}


	public Mono<ServerResponse> search(ServerRequest serverRequest) {

		long start = System.currentTimeMillis();

		return serverRequest.bodyToMono(SearchRequest.class)
				.doOnNext(searchRequestValidator::validate)
				.flatMap(req -> iexTradingClient.search(getIexQueryParams(req)).map(SearchResult::new))
				.flatMap(req -> google.search(req).map(SearchResult::new))
				.onErrorResume(this::handleError)
				.flatMap(response ->

						ServerResponse.status(response.getResponseStatus().getHttpCode())
								.contentType(MediaType.APPLICATION_JSON)
								.syncBody(response)

				).doFinally(signal -> {
							logger.info("endpoints.symbols.search.responsetime=" + (System.currentTimeMillis() - start));
						}
				);
	}

	private LinkedMultiValueMap<String, String> getIexQueryParams(SearchRequest sr) {
		LinkedMultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("symbols", StringUtils.join(sr.getSymbols(), ","));
		if(!sr.getContent_types().isEmpty())
			map.add("types", StringUtils.join(sr.getContent_types(), ","));
		return map;
	}

	private Mono<? extends SearchResult> handleError(Throwable error) {
		logger.error("Error occurs while processing request: ", error);
		return Mono.just(new SearchResult(error));
	}

}
