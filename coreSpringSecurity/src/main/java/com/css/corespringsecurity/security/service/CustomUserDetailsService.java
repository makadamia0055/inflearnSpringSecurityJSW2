package com.css.corespringsecurity.security.service;

import com.css.corespringsecurity.domain.entity.Account;
import com.css.corespringsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private HttpServletRequest request;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Account account= userRepository.findByUsername(username);

        if(account==null){
            if(userRepository.countByUsername(username)== 0){
                throw new UsernameNotFoundException("No user found with username : " + username);
            }
        }
        Set<String> userRoles = account.getUserRoles()
                .stream()
                .map(userRole -> userRole.getRoleName())
                .collect(Collectors.toSet());
        List<GrantedAuthority> collect = userRoles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        AccountContext accountContext = new AccountContext(account, collect);

        return accountContext;

    }
}
