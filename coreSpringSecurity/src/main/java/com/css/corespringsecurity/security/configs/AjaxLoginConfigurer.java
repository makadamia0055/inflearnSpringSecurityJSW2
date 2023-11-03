package com.css.corespringsecurity.security.configs;

import com.css.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class AjaxLoginConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractAuthenticationFilterConfigurer<H, AjaxLoginConfigurer<H>, AjaxLoginProcessingFilter> {

    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private AuthenticationManager authenticationManager;

    public AjaxLoginConfigurer(){
        super(new AjaxLoginProcessingFilter(), null);
    }

    @Override
    public void init(H http) throws Exception {
        super.init(http);
    }

    @Override
    public void configure(H http) throws Exception {
        if(authenticationManager == null){
            authenticationManager = http.getSharedObject(AuthenticationManager.class);
            //HttpSecurity 객체를 통해 공유 객체를 저장하고 가져올 수 있는 API
        }
        // 생성자에서 설정한 AjaxLoginProcessingFilter 를 가져와 authenticationManager, successHandler, FailureHandler를 설정
        getAuthenticationFilter().setAuthenticationManager(authenticationManager);
        getAuthenticationFilter().setAuthenticationSuccessHandler(successHandler);
        getAuthenticationFilter().setAuthenticationFailureHandler(failureHandler);

        SessionAuthenticationStrategy sessionAuthenticationStrategy
                = http.getSharedObject(SessionAuthenticationStrategy.class);
        if(sessionAuthenticationStrategy !=null){
            getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if(rememberMeServices !=null){
            getAuthenticationFilter().setRememberMeServices(rememberMeServices);

        }
        // 공유 객체 저장소에 설정한 AjaxLoginProcessingFilter를 넣어줌.
        http.setSharedObject(AjaxLoginProcessingFilter.class, getAuthenticationFilter());
        // 필터 설정
        http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);


    }
    @Override
    public AjaxLoginConfigurer<H> loginPage(String loginPage) {
        return super.loginPage(loginPage);
    }
    public AjaxLoginConfigurer<H> successHandlerAjax(AuthenticationSuccessHandler successHandler){
        this.successHandler = successHandler;
        return this;
    }

    public AjaxLoginConfigurer<H> failureHandlerAjax(AuthenticationFailureHandler failureHandler){
        this.failureHandler = failureHandler;
        return this;
    }

    public AjaxLoginConfigurer<H> setAuthenticationManager(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
        return this;
    }
    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl){
        return new AntPathRequestMatcher(loginProcessingUrl, "POST");
    }

}
