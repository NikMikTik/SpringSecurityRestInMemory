package com.springsecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class Controller {

	@Autowired
	private UserDetailsService userService;

	@GetMapping("/user")
	public ResponseEntity<String> userGreeting(Authentication authentication) {
		return new ResponseEntity<String>("Spring Security In-memory Authentication Example: " + authentication.getPrincipal().toString(),HttpStatus.ACCEPTED);
	}

	@GetMapping("/admin")
	public String adminGreeting(Authentication authentication) {
		return "Spring Security In-memory Authentication Example: " + authentication.getDetails();
	}
	@GetMapping("/expired")
	public String expiredGreeting(Authentication authentication) {
		return "Login Again.. Session Expired... "+authentication.getName();
	}

}
