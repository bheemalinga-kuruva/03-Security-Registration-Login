package com.bhim.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.bhim.model.UserEntity;
import com.bhim.repository.UserRepository;



@RestController
public class UserRestController {

	@Autowired
	private UserRepository userepo;

	@Autowired
	private PasswordEncoder pwdEncoder;

	@Autowired
	private AuthenticationManager authManager;

	@PostMapping("/login")
	public ResponseEntity<String> loginCheck(@RequestBody UserEntity user) {
		UsernamePasswordAuthenticationToken token = 
				new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPwd());
		try {
			Authentication authenticate = authManager.authenticate(token);
			if (authenticate.isAuthenticated()) {
				return new ResponseEntity<String>("Welcome to Our Application ", HttpStatus.OK);
			}
		} catch (Exception e) {
		}
		return new ResponseEntity<String>("Invalid Credentials", HttpStatus.UNAUTHORIZED);
	}

	@PostMapping("/register")
	public ResponseEntity<String> registration(@RequestBody UserEntity user) {
		String encodedPwd = pwdEncoder.encode(user.getPwd());
		user.setPwd(encodedPwd);
		userepo.save(user);
		return new ResponseEntity<String>("User Registered", HttpStatus.CREATED);
	}

}
