package com.css.corespringsecurity.security.provider;

import com.css.corespringsecurity.security.common.FormWebAuthenticationDetails;
import com.css.corespringsecurity.security.service.AccountContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class FormAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override // 실제 인증 처리를 하는 메소드
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String)authentication.getCredentials(); // 오브젝트 타입으로 리턴됨
        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);
        // UserDetailsService에서 loadUserByUsername(username)로 User객체(를 상속한 AccountContext 객체)를 가져옴.
        if(!passwordEncoder.matches(password, accountContext.getAccount().getPassword())){
            throw new BadCredentialsException("BadCredentialsException");
        } // 비밀번호 검증
        FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = formWebAuthenticationDetails.getSecretKey();
        if(secretKey==null || !"secret".equals(secretKey)){
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
        }

        // id검증(username에 맞는 객체 가져오는 것으로)과 pw검증을 마쳤으니 Authentication의 구현체인 UsernamePasswordAuthenticationToken을 리턴
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
        return authenticationToken;
    }

    @Override // 요청받은 인증객체를 지원하는지 여부를 리턴해주는 메소드.
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
