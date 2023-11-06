package com.css.corespringsecurity.service.impl;

import com.css.corespringsecurity.domain.entity.Resources;
import com.css.corespringsecurity.repository.ResourcesRepository;
import com.css.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

public class SecurityResourceServiceImpl implements SecurityResourceService {

    private ResourcesRepository resourceRepository;


    public SecurityResourceServiceImpl(ResourcesRepository resourceRepository) {
        this.resourceRepository = resourceRepository;
    }

    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result= new LinkedHashMap<>();
        List<Resources> resourcesList = resourceRepository.findAllResources();
        resourcesList.forEach(re -> {
            List<ConfigAttribute> configAttributesList = new ArrayList<>();
            re.getRoleSet().forEach(role -> {
                configAttributesList.add(new SecurityConfig(role.getRoleName()));
                result.put(new AntPathRequestMatcher(re.getResourceName()), configAttributesList);

            });

        });
        return result;
    }
}
