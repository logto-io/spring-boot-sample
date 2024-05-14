package com.example.securingweb;

import java.security.Principal;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;

@Controller
@RequestMapping("/user")
public class UserController {
  @Value("${spring.security.oauth2.resourceserver.jwt.audiences}")
  private String audience;

  @GetMapping
  public String user(Model model, Principal principal) {
    if (principal instanceof OAuth2AuthenticationToken) {
      OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) principal;
      OAuth2User oauth2User = token.getPrincipal();
      Map<String, Object> attributes = oauth2User.getAttributes();

      model.addAttribute("username", attributes.get("username"));
      model.addAttribute("email", attributes.get("email"));
      model.addAttribute("sub", attributes.get("sub"));
    }

    return "user";
  }

  @Autowired
  private OAuth2AuthorizedClientService authorizedClientService;

  @GetMapping("/getTokens")
  public String getTokens(Model model, OAuth2AuthenticationToken principal) {

    // Get new access token using refresh token for a given resource
    getNewAccessToken(principal, audience);

    OAuth2AccessToken accessToken = getAccessToken(principal);
    OAuth2RefreshToken refreshToken = getRefreshToken(principal);

    if (refreshToken != null) {
      model.addAttribute("refreshToken", refreshToken.getTokenValue());
    }

    if (accessToken != null) {
      model.addAttribute("accessToken", accessToken.getTokenValue());
    }

    return "token";
  }

  private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken principal) {
    if (principal instanceof OAuth2AuthenticationToken) {
      OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) principal;

      return authorizedClientService
          .loadAuthorizedClient(token.getAuthorizedClientRegistrationId(), token.getName());
    }

    return null;
  }

  public OAuth2RefreshToken getRefreshToken(OAuth2AuthenticationToken principal) {
    OAuth2AuthorizedClient client = getAuthorizedClient(principal);

    if (client != null && client.getRefreshToken() != null) {
      return client.getRefreshToken();
    }

    return null;
  }

  public OAuth2AccessToken getAccessToken(OAuth2AuthenticationToken principal) {
    OAuth2AuthorizedClient client = getAuthorizedClient(principal);

    if (client != null) {
      return client.getAccessToken();
    }

    return null;
  }

  private void updateAuthorizedClient(OAuth2AuthenticationToken principal, OAuth2AuthorizedClient client,
      OAuth2AccessToken newAccessToken,
      OAuth2RefreshToken newRefreshToken) {

    OAuth2AuthorizedClient newClient = new OAuth2AuthorizedClient(client.getClientRegistration(),
        client.getPrincipalName(), newAccessToken, newRefreshToken);

    authorizedClientService.saveAuthorizedClient(newClient, principal);
  }

  // Get new access token using refresh token for a given resource
  private void getNewAccessToken(OAuth2AuthenticationToken principal, String resource) {
    OAuth2AuthorizedClient client = getAuthorizedClient(principal);

    if (client == null) {
      throw new RuntimeException("No authorized client found");
    }

    OAuth2RefreshToken refreshToken = client.getRefreshToken();

    if (refreshToken == null) {
      throw new RuntimeException("No refresh token found");
    }

    RestTemplate restTemplate = new RestTemplate();

    MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
    formData.add("grant_type", "refresh_token");
    formData.add("refresh_token", refreshToken.getTokenValue());
    formData.add("client_id", client.getClientRegistration().getClientId());
    formData.add("client_secret",
        client.getClientRegistration().getClientSecret());
    formData.add("resource", resource);

    HttpHeaders headers = new HttpHeaders();
    headers.add("Content-Type", "application/x-www-form-urlencoded");
    HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(formData, headers);

    ResponseEntity<Map> response = restTemplate
        .postForEntity(client.getClientRegistration().getProviderDetails().getTokenUri(),
            request, Map.class);

    String newAccessToken = response.getBody().get("access_token").toString();
    String newRefreshToken = response.getBody().get("refresh_token").toString();

    System.out.println(response.getBody());

    // decode the new access token to get the expiration time
    Jwt jwt = decodeAccessToken(newAccessToken, client.getClientRegistration().getProviderDetails().getJwkSetUri());

    OAuth2AccessToken newOAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        newAccessToken, jwt.getIssuedAt(), jwt.getExpiresAt());

    OAuth2RefreshToken newOAuth2RefreshToken = new OAuth2RefreshToken(newRefreshToken, jwt.getIssuedAt());

    // Update the authorized client with new access token and refresh token
    updateAuthorizedClient(principal, client, newOAuth2AccessToken, newOAuth2RefreshToken);
  }

  private JwtDecoder customJwtDecoder(String jwkSetUri) {
    NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
        // The decoder should support the JWS algorithm: ES384
        .jwsAlgorithm(SignatureAlgorithm.ES384)
        // The decoder should support the token type: Access Token + JWT.
        .jwtProcessorCustomizer(customizer -> customizer.setJWSTypeVerifier(
            new DefaultJOSEObjectTypeVerifier<SecurityContext>(new JOSEObjectType("at+jwt"))))
        .build();

    return jwtDecoder;
  }

  // Decode the access token to get the expiration time and other details
  private Jwt decodeAccessToken(String accessToken, String jwkSetUri) {
    Jwt jwt = customJwtDecoder(jwkSetUri).decode(accessToken);

    return jwt;
  }
}
