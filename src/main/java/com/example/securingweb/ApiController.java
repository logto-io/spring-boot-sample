package com.example.securingweb;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api")
public class ApiController {

  @GetMapping("/protected")
  public ResponseEntity<Map<String, Boolean>> testApi() {
    Map<String, Boolean> response = new HashMap<>();
    response.put("success", true);
    return ResponseEntity.ok(response);
  }
}
