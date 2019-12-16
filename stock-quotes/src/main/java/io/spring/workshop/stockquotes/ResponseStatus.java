package io.spring.workshop.stockquotes;

public enum ResponseStatus {

    /**
     * Everything is good
     */
    OK(200),

    /**
     * Something structurally incorrect about
     * the input message from the client.
     */
    ClientError(400),

    /**
     * Something went wrong on the server
     * and it's unlikely to work again
     */
    ServerError(500),


    /**
     * Something went wrong on the server
     * or its dependencies and it may work
     * if retried.
     */
    RetryableServerError(503);


    private int httpCode;

    ResponseStatus(int httpCode) {
        this.httpCode = httpCode;
    }

    public int getHttpCode() {
        return httpCode;
    }
}
