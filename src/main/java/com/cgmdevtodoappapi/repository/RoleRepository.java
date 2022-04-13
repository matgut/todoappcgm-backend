package com.cgmdevtodoappapi.repository;

import com.cgmdevtodoappapi.entity.Role;
import com.cgmdevtodoappapi.enumeration.ERole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
