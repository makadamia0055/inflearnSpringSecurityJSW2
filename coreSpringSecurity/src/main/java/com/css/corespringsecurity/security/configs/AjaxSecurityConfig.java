package com.css.corespringsecurity.security.configs;

import com.css.corespringsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import com.css.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import com.css.corespringsecurity.security.handler.AjaxAccessDeniedHandler;
import com.css.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import com.css.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import com.css.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import com.css.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Order(0)
public class AjaxSecurityConfig {
    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;
    @Bean
    public SecurityFilterChain ajaxLoginSecurityConfig(HttpSecurity http) throws Exception{
        http.antMatcher("/api/**")
                .authorizeRequests()
                .antMatchers("/api/messages").hasRole("MANAGER")
                .antMatchers("/api/login").permitAll()
                .anyRequest().authenticated()


        .and()
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                ;

        http
                .exceptionHandling()
                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                .accessDeniedHandler(ajaxAccessDeniedHandler());
        http.csrf().disable();

//        customConfigurerAjax(http);
        return http.build();
    }

//    private void customConfigurerAjax(HttpSecurity http) throws Exception {
//        http.apply(new AjaxLoginConfigurer<>())
//                .successHandlerAjax(ajaxAuthenticationSuccessHandler())
//                .failureHandlerAjax(ajaxAuthenticationFailureHander())
//                .loginPage("/api/login")
//                .loginProcessingUrl("/api/login")
//                .setAuthenticationManager(authenticationManager(authenticationConfiguration))
//                ;
//
//    }

    @Bean
    public AccessDeniedHandler ajaxAccessDeniedHandler() {
        return new AjaxAccessDeniedHandler();
    }

    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHander());
        return ajaxLoginProcessingFilter;
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)throws Exception{
        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
        authenticationManager.getProviders().add(ajaxAuthenticationProvider()); // ajaxAuthenticationProvider 추가
        return authenticationManager;
    }

    @Bean
    public AjaxAuthenticationProvider ajaxAuthenticationProvider(){
        return new AjaxAuthenticationProvider();
    }
    @Bean
    public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler(){
        return new AjaxAuthenticationSuccessHandler();
    }
    @Bean
    public AuthenticationFailureHandler ajaxAuthenticationFailureHander(){
        return new AjaxAuthenticationFailureHandler();
    }

}
