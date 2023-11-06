package com.css.corespringsecurity.service.impl;

import com.css.corespringsecurity.domain.entity.Account;
import com.css.corespringsecurity.repository.UserRepository;
import com.css.corespringsecurity.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userService")
public class UserServiceImpl implements UserService {
    @Autowired
    UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
