package com.bhim.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.bhim.service.MyUserDetailesService;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig {
    @Autowired	
	private MyUserDetailesService userservice;
	@Bean
	 PasswordEncoder pwdEncoder() {
		return new BCryptPasswordEncoder();
	}

	public void configureUsers(AuthenticationManagerBuilder auth) throws Exception{
	auth.userDetailsService(userservice)
	 .passwordEncoder(pwdEncoder());
	}

	
	@Bean
	public AuthenticationProvider authProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userservice);
		authProvider.setPasswordEncoder(pwdEncoder());
		return authProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
		
	@Bean
      SecurityFilterChain securityConfig(HttpSecurity http) throws Exception {
		return http.csrf(csrf -> csrf
                .disable())
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/register", "/login")
                        .permitAll())
                .build();	
	 /*	http.authorizeHttpRequests((authorize) -> authorize		
				.requestMatchers("/register", "/login").permitAll()
				.anyRequest().authenticated()
				)
				.httpBasic(withDefaults())
				.formLogin(withDefaults());
		return http.build();
		
		*/
	}
}
