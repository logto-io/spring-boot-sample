package com.example.securingweb;

import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.DefaultSecurityFilterChain;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity

public class WebSecurityConfig {
  @Value("${spring.security.oauth2.resourceserver.jwt.audiences}")
  private String audience;

  @Value("${spring.security.oauth2.client.provider.logto.jwk-set-uri}")
  private String jwksUri;

  @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
  private String issuer;

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @Bean
  public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
    OidcIdTokenDecoderFactory idTokenDecoderFactory = new OidcIdTokenDecoderFactory();
    idTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> SignatureAlgorithm.ES384);
    return idTokenDecoderFactory;
  }

  @Bean
  public JwtDecoder jwtDecoder() {
    NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwksUri)
        // Logto uses the ES384 algorithm to sign the JWTs by default.
        .jwsAlgorithm(SignatureAlgorithm.ES384)
        // The decoder should support the token type: Access Token + JWT.
        .jwtProcessorCustomizer(customizer -> customizer.setJWSTypeVerifier(
            new DefaultJOSEObjectTypeVerifier<SecurityContext>(new JOSEObjectType("at+jwt"))))
        .build();

    jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
        new AudienceValidator(audience),
        new JwtIssuerValidator(issuer),
        new JwtTimestampValidator()));

    return jwtDecoder;
  }

  @Bean
  @Order(1)
  public DefaultSecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/api/**")
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(Customizer.withDefaults()))
        .authorizeHttpRequests(requests -> requests
            .anyRequest().authenticated());

    return http.build();
  }

  // Web page security configuration
  @Bean
  @Order(2)
  public DefaultSecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(requests -> requests
            .requestMatchers("/user", "/token").authenticated()
            .anyRequest().permitAll())
        .oauth2Login(oauth2 -> oauth2
            .authorizationEndpoint(authorization -> authorization.authorizationRequestResolver(
                authorizationRequestResolver(this.clientRegistrationRepository)))
            .successHandler(new CustomSuccessHandler()))
        .logout(logout -> logout.logoutSuccessHandler(new CustomLogoutHandler()));

    return http.build();
  }

  private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
      ClientRegistrationRepository clientRegistrationRepository) {
    DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
        clientRegistrationRepository, "/oauth2/authorization");
    authorizationRequestResolver.setAuthorizationRequestCustomizer(authorizationRequestCustomizer());

    return authorizationRequestResolver;
  }

  private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
    return customizer -> customizer.additionalParameters(params -> {
      // Set the prompt parameter to "consent". User will be auto consent if Logto has
      // a valid session. prompt=consent is required to obtain a refresh token
      params.put("prompt", "consent");

      // Set the prompt parameter to "login" to force the user to sign in every time
      // params.put("prompt", "login");

      params.put("resource", audience);
    });
  }
}
