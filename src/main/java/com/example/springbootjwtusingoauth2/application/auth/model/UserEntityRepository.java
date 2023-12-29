package com.example.springbootjwtusingoauth2.application.auth.model;

import com.example.springbootjwtusingoauth2.infra.security.UserDetailsRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserEntityRepository extends UserDetailsRepository<UserEntity, Long> {
}
