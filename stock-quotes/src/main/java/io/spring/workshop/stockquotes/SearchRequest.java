package io.spring.workshop.stockquotes;

import java.util.HashSet;
import java.util.Set;

public class SearchRequest {
    // set of stock symbols limited to 100
    private Set<String> symbols = new HashSet<>();

    // types of info to request - limited to content_types=quote,news,chart
    private Set<String> content_types = new HashSet<>();

    public Set<String> getSymbols() {
        return symbols;
    }

    public void setSymbols(Set<String> symbols) {
        this.symbols = symbols;
    }

    public Set<String> getContent_types() {
        return content_types;
    }

    public void setContent_types(Set<String> content_types) {
        this.content_types = content_types;
    }
}
