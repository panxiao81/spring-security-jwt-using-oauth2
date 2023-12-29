package com.example.springbootjwtusingoauth2.application.auth.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Table(name = "authority")
@Data
public class Authority implements GrantedAuthority {
    @Id
    @GeneratedValue
    private Long id;
    private String name;

    public Authority(Long id, String name) {
        this.id = id;
        this.name = name;
    }

    public Authority() {

    }

    @Override
    public String getAuthority() {
        return this.name;
    }
}
