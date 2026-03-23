package com.javaintershipauthservice.repository;

import com.javaintershipauthservice.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RoleRepository extends JpaRepository<Role, Long> {
    List<Role> findByUser_Id(Long userId);
}

