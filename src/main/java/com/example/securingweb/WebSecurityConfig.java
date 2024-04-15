package com.example.securingweb;

import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.DefaultSecurityFilterChain;

@Configuration
@EnableWebSecurity

public class WebSecurityConfig {
  @Value("${spring.security.oauth2.client.provider.logto.jwk-set-uri}")
  private String jwkSetUri;

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @Bean
  public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
    OidcIdTokenDecoderFactory idTokenDecoderFactory = new OidcIdTokenDecoderFactory();
    idTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> SignatureAlgorithm.ES384);
    return idTokenDecoderFactory;
  }

  @Bean
  public DefaultSecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(requests -> requests
            .requestMatchers("/", "/home").permitAll()
            .anyRequest().authenticated())
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
      // Set the prompt parameter to "login" to force the user to log in, otherwise
      // user will auto consent if Logto has a valid session
      params.put("prompt", "login");

      // params.put("resource", "https://test.logto.io/");
    });
  }
}
