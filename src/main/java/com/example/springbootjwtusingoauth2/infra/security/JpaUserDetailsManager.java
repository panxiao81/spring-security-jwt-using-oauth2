package com.example.springbootjwtusingoauth2.infra.security;

import org.springframework.beans.BeanUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.ReflectionUtils;

public class JpaUserDetailsManager<T extends UserDetails> implements UserDetailsManager, UserDetailsService {
    private final UserDetailsRepository<T, ?> repository;

    public JpaUserDetailsManager(UserDetailsRepository<T, ?> userDetailsRepository) {
        this.repository = userDetailsRepository;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void createUser(UserDetails user) {
         repository.saveAndFlush((T) user);
    }

    @Override
    public void updateUser(UserDetails user) {
        T user1 = repository.findByUsername(user.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("user not found"));

        BeanUtils.copyProperties(user, user1, "password");
        repository.saveAndFlush(user1);
    }

    @Override
    public void deleteUser(String username) {
        T user = repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        repository.delete(user);
    }

    protected Authentication createNewAuthentication(Authentication currentAuth, String newPassword) {
        UserDetails user = loadUserByUsername(currentAuth.getName());
        UsernamePasswordAuthenticationToken newAuthentication = UsernamePasswordAuthenticationToken.authenticated(user,
                null, user.getAuthorities());
        newAuthentication.setDetails(currentAuth.getDetails());
        return newAuthentication;
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        SecurityContextHolderStrategy contextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
        Authentication currentUser = contextHolderStrategy.getContext().getAuthentication();
        if (currentUser == null) {
            throw new AccessDeniedException(
                    "Can't change password as no Authentication object found in context " + "for current user."
            );
        }

        String name = currentUser.getName();

        T user = repository.findByUsername(name)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Change password using reflection
        try {
            ReflectionUtils.setField(user.getClass().getField("password"), user, newPassword);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }

        repository.saveAndFlush(user);

        Authentication newAuthentication = createNewAuthentication(currentUser, newPassword);
        SecurityContext context = contextHolderStrategy.createEmptyContext();
        context.setAuthentication(newAuthentication);
        contextHolderStrategy.setContext(context);
    }

    @Override
    public boolean userExists(String username) {
        return repository.existsByUsername(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User %s not found".formatted(username)));
    }
}
