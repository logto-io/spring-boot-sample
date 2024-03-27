# Logto Spring Boot Web Application Sample

This is a sample project to demonstrate how to integrate [Logto](https://logto.io) authentication with a Spring Boot web application.

## Pre-requisites

Register an account on [Logto](https://logto.io) and create a new application to get the client id and client secret.

## Configuration

```properties
spring.security.oauth2.client.registration.logto.client-id=<your-client-id>
spring.security.oauth2.client.registration.logto.client-secret=<your-client-secret>
spring.security.oauth2.client.registration.logto.provider=logto
spring.security.oauth2.client.provider.logto.issuer-uri=http://localhost:3001/oidc
spring.security.oauth2.client.provider.logto.authorization-uri=http://localhost:3001/oidc/auth
spring.security.oauth2.client.provider.logto.jwk-set-uri=http://localhost:3001/oidc/jwks
```

- client-id: The client id of the application created on Logto.
- client-secret: The client secret of the application created on Logto.
- issuer-uri: The issuer URI of the Logto instance. ${logto-endpoint}/oidc
- authorization-uri: The authorization URI of the Logto instance. ${logto-endpoint}/oidc/auth
- jwk-set-uri: The JWK set URI of the Logto instance. ${logto-endpoint}/oidc/jwks

## Start

```sh
gradle bootRun
```
