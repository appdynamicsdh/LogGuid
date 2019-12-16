package io.spring.workshop.stockquotes;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;

public class SearchResult {
    private JsonNode results;
    private List<String> errors = new ArrayList<>();

    @JsonIgnore
    private ResponseStatus responseStatus = ResponseStatus.OK;

    public SearchResult() {
    }

    public SearchResult(JsonNode results) {
        this.results = results;
    }

    public SearchResult(Throwable t) {
        if(t != null){
            this.responseStatus = ResponseStatus.ClientError;
            this.errors.add(t.getMessage());
        }
    }

    public JsonNode getResults() {
        return results;
    }

    public void setResults(JsonNode results) {
        this.results = results;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    public ResponseStatus getResponseStatus() {
        return responseStatus;
    }

    public void setResponseStatus(ResponseStatus responseStatus) {
        this.responseStatus = responseStatus;
    }
}
