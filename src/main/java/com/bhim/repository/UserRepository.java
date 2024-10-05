package com.bhim.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bhim.model.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

	public UserEntity findByuserName(String userName);
}
