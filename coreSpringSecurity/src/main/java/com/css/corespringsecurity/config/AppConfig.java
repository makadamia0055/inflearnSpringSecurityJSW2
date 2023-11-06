package com.css.corespringsecurity.config;

import com.css.corespringsecurity.repository.ResourcesRepository;
import com.css.corespringsecurity.service.SecurityResourceService;
import com.css.corespringsecurity.service.impl.SecurityResourceServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository){
        SecurityResourceService securityResourceService = new SecurityResourceServiceImpl(resourcesRepository);
        return securityResourceService;
    }
}
