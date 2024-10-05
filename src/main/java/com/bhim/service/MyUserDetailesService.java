package com.bhim.service;
import java.util.Collections;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.bhim.model.UserEntity;
import com.bhim.repository.UserRepository;

@Service
public class MyUserDetailesService implements UserDetailsService {

	@Autowired
	private UserRepository userRepo;
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	
		UserEntity user = userRepo.findByuserName(username);
		return  new User(user.getUserName(),user.getPwd(),Collections.emptyList());
		
	}

	
}
