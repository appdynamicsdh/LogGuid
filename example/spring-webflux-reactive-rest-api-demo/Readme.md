# AppDynamics Example Reactive Rest APIs with Spring WebFlux and Reactive MongoDB


## Requirements

1. Java - 1.8.x

2. Maven - 3.x.x

3. MongoDB - 3.x.x

## Steps to Setup

**1. Build and run the app using maven**

```bash
cd spring-webflux-reactive-rest-api-demo

mvn package

Create a backend (note server port is 8090):

java -javaagent:C:\appdynamics\AppServerAgent-4.5.2.24246\javaagent.jar -Dappagent.install.dir=C:\appdynamics\AppServerAgent-4.5.2.24246\ -Dappdynamics.agent.nodeName=WebFluxN -Dappdynamics.agent.tierName=WebFluxT -Dallow.unsigned.sdk.extension.jars=true -jar webflux-demo-0.0.1-SNAPSHOT.jar --server.port=8090

Create a frontend:

java -javaagent:C:\appdynamics\AppServerAgent-4.5.2.24246\javaagent.jar -Dappagent.install.dir=C:\appdynamics\AppServerAgent-4.5.2.24246\ -Dappdynamics.agent.nodeName=WebFluxN2 -Dappdynamics.agent.tierName=WebFluxT2 -Dallow.unsigned.sdk.extension.jars=true -jar webflux-demo-0.0.1-SNAPSHOT.jar

Apply load:
while (true); do curl http://localhost:8080/test; done


```

## Exploring the Rest APIs

The application defines following REST APIs

```
1. GET /tweets - Get All Tweets

2. POST /tweets - Create a new Tweet

3. GET /tweets/{id} - Retrieve a Tweet by Id

3. PUT /tweets/{id} - Update a Tweet

4. DELETE /tweets/{id} - Delete a Tweet

4. GET /stream/tweets - Stream tweets to a browser as Server-Sent Events
```

