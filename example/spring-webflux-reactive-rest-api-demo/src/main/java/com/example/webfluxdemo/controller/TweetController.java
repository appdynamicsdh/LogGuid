package com.example.webfluxdemo.controller;

import com.appdynamics.apm.appagent.api.AgentDelegate;
import com.appdynamics.apm.appagent.api.ITransactionDemarcator;
import com.example.webfluxdemo.exception.TweetNotFoundException;
import com.example.webfluxdemo.model.Tweet;
import com.example.webfluxdemo.payload.ErrorResponse;
import com.example.webfluxdemo.repository.TweetRepository;
//import io.opentracing.Span;
//import io.opentracing.Tracer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.ipc.netty.http.client.HttpClientRequest;

import javax.validation.Valid;
import java.time.Duration;
import java.util.HashSet;
import java.util.UUID;

/**
 * Created by rajeevkumarsingh on 08/09/17.
 */
@RestController
public class TweetController {

   // @Autowired
   // Tracer tracer;

    @Autowired
    private TweetRepository tweetRepository;

    //1. AppD :  Fetch the appdynamics transaction delegate
    private static final ITransactionDemarcator transactionDemarcator = AgentDelegate.getTransactionDemarcator();

    private String searchTrans = "";


    public Mono<ServerResponse> search(final String txId) {

        // 2.  AppD :  Explicitly begin the transaction using the AppD API

                //transactionDemarcator.
                //ServerRequest serverRequest = new Ser
                return ServerResponse.ok().syncBody(new String())

                        .doFinally(signalType -> {
                            System.out.println("Blah");
                            //transactionDemarcator.addCurrentThreadToTransaction(txId,"BLAH BLAH",null);
                            try {
                                Thread.sleep(3000);
                                System.out.println("Test");
                            } catch (Exception e) {
                            } finally {
                            }
                            //transactionDemarcator.removeCurrentThreadFromTransaction(null);
                        }).doFinally(s2 -> System.out.println("BOOOOOOOOOM!"));



    }

   @GetMapping("/test")
    public Mono<String> test(){
        //love you...
        long time = System.currentTimeMillis();
       //WebClient client2 = WebClient.create("http://www.google.com");

       WebClient client2 = WebClient.create("http://localhost:8090/tweets");








       return                client2.get()
               .retrieve()
               .bodyToMono(String.class);
    }

    @GetMapping("/tweets")
    public Flux<Tweet> getAllTweets() {

        //String searchTrans = transactionDemarcator.beginOriginatingTransactionAndAddCurrentThread("search3", null);
        /*try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }*/
        search(searchTrans).subscribe();
        System.out.println("Dave");

        Flux<Tweet> tweets  =  tweetRepository.findAll();
        System.out.println(searchTrans);

        tweets.subscribe();
       // transactionDemarcator.endOriginatingTransactionAndRemoveCurrentThread();

        return tweets;
    }

    @PostMapping("/tweets")
    public Mono<Tweet> createTweets(@Valid @RequestBody Tweet tweet) {
        return tweetRepository.save(tweet);
    }

    @GetMapping("/tweets/{id}")
    public Mono<ResponseEntity<Tweet>> getTweetById(@PathVariable(value = "id") String tweetId) {
        return tweetRepository.findById(tweetId)
                .map(savedTweet -> ResponseEntity.ok(savedTweet))
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @PutMapping("/tweets/{id}")
    public Mono<ResponseEntity<Tweet>> updateTweet(@PathVariable(value = "id") String tweetId,
                                                   @Valid @RequestBody Tweet tweet) {
        return tweetRepository.findById(tweetId)
                .flatMap(existingTweet -> {
                    existingTweet.setText(tweet.getText());
                    return tweetRepository.save(existingTweet);
                })
                .map(updateTweet -> new ResponseEntity<>(updateTweet, HttpStatus.OK))
                .defaultIfEmpty(new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @DeleteMapping("/tweets/{id}")
    public Mono<ResponseEntity<Void>> deleteTweet(@PathVariable(value = "id") String tweetId) {

        return tweetRepository.findById(tweetId)
                .flatMap(existingTweet ->
                        tweetRepository.delete(existingTweet)
                            .then(Mono.just(new ResponseEntity<Void>(HttpStatus.OK)))
                )
                .defaultIfEmpty(new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    // Tweets are Sent to the client as Server Sent Events
    @GetMapping(value = "/stream/tweets", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<Tweet> streamAllTweets() {
        return tweetRepository.findAll();
    }




    /*
        Exception Handling Examples (These can be put into a @ControllerAdvice to handle exceptions globally)
    */

    @ExceptionHandler(DuplicateKeyException.class)
    public ResponseEntity handleDuplicateKeyException(DuplicateKeyException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse("A Tweet with the same text already exists"));
    }

    @ExceptionHandler(TweetNotFoundException.class)
    public ResponseEntity handleTweetNotFoundException(TweetNotFoundException ex) {
        return ResponseEntity.notFound().build();
    }

}
