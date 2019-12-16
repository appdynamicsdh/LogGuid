package io.spring.workshop.stockquotes;

public class GeneralException extends RuntimeException {

    private ResponseStatus responseStatus;

    public GeneralException(ResponseStatus responseStatus) {
        this.responseStatus = responseStatus;
    }

    public GeneralException(String message, ResponseStatus responseStatus) {
        super(message);
        this.responseStatus = responseStatus;
    }

    public ResponseStatus getResponseStatus() {
        return responseStatus;
    }
}
