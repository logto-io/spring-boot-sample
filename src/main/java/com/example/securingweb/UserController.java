package com.example.securingweb;

import java.security.Principal;
import java.util.Map;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/user")
public class UserController {
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
}
