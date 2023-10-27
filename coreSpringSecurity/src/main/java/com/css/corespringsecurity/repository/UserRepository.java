package com.css.corespringsecurity.repository;

import com.css.corespringsecurity.domain.Account;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

public interface UserRepository extends JpaRepository<Account, Long> {


    Account findByUsername(String username);
}
