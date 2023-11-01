package com.css.corespringsecurity.security.filter;

import com.css.corespringsecurity.domain.AccountDto;
import com.css.corespringsecurity.security.token.AjaxAuthenticationToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    public AjaxLoginProcessingFilter(){ // 필터 작동 조건을 주기 위해 필터 작동조건 1. /api/login url 2. 요청 형식이 Ajax
        super(new AntPathRequestMatcher("/api/login")); // 필터 작동 조건 1.
    }
    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if(!isAjax(request)){
            throw new IllegalStateException("authentication is not supported");
        }
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        if(StringUtils.isEmpty(accountDto.getUsername())||StringUtils.isEmpty(accountDto.getPassword())){
            throw new IllegalArgumentException("Username or Password is empty");

        }
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

        // 그리고 이 토큰을 인증 처리를 실제로 수행하는 AuthenticationManager 에게 전달.
        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }

    private boolean isAjax(HttpServletRequest request) { // 어떻게 보낸 데이터를 판별할 것인가 : 백엔드와 프론트의 사전 규약
        if("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))){
            return true;
        }
        return false;
    }

}
