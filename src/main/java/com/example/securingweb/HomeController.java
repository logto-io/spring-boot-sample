package com.example.securingweb;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
  @GetMapping({ "/", "/home" })
  public String home(Principal principal) {
    return principal != null ? "redirect:/user" : "home";
  }
}
