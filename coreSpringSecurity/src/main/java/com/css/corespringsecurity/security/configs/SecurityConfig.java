package com.css.corespringsecurity.security.configs;

import com.css.corespringsecurity.security.common.FormWebAuthenticationDetailsSource;
import com.css.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import com.css.corespringsecurity.security.handler.FormAccessDeniedHandler;
import com.css.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import com.css.corespringsecurity.security.provider.FormAuthenticationProvider;
import com.css.corespringsecurity.service.SecurityResourceService;
import org.hibernate.jpa.boot.spi.ProviderChecker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

@EnableWebSecurity
@Order(1)
public class SecurityConfig {

    @Autowired // AuthenticationDetailsSource로 등록할 시 메소드 체이닝에서 제너럴 값이 사라지는 오류 생김.
    private AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;

    @Autowired
    private AuthenticationFailureHandler formAuthenticationFailureHandler;

    @Autowired
    private AuthenticationSuccessHandler formAuthenticationSuccessHandler;
    @Autowired
    private SecurityResourceService securityRecourceService;


    @Bean
    public SecurityFilterChain formLoginFilterChain(HttpSecurity http) throws Exception{
        http
                .authorizeRequests()
                .antMatchers("/", "/users/login/**","/users", "/login*").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
        .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
        .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)
                // 우리가 만든 AuthenticationDetailsSource인 FormWebAuthenticationDetailsSource 를 등록
                .defaultSuccessUrl("/")
                .successHandler(formAuthenticationSuccessHandler)
                .failureHandler(formAuthenticationFailureHandler)
                .permitAll() // 로그인은 인증을 받지 않은 사용자라도 접근 가능해야 하기 때문에.
        .and()
                .addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class)
        ;


        return http.build();
    }
    @Bean // 정적 파일들을 보안 필터 거치지 않게 해주는 설정 등록
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }



    @Bean
    public FormAuthenticationProvider formAuthenticationProvider(){
        return new FormAuthenticationProvider();

    }
    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        FormAccessDeniedHandler accessDeniedHandler = new FormAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    @Bean
    public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {

        // FilterSecurityInterceptor는 세가지를 설정해주어야 함.
        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
        filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        // 가장 보편적인 AffirmativeBased로 설정
        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
        //인증 매니저 설정
        filterSecurityInterceptor.setAuthenticationManager(authenticationConfiguration().getAuthenticationManager());
        return filterSecurityInterceptor;
    }
    @Bean
    public AuthenticationConfiguration authenticationConfiguration(){
        return new AuthenticationConfiguration();
    }
    @Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
        return new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean().getObject());
    }

    private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
        UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
        urlResourcesMapFactoryBean.setSecurityResourceService(securityRecourceService);
        return urlResourcesMapFactoryBean;
    }


    private AccessDecisionManager affirmativeBased() {
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecisitionVoters());
        return affirmativeBased;
    }

    private List<AccessDecisionVoter<?>> getAccessDecisitionVoters() {
        return Arrays.asList(new RoleVoter());
    }


}
