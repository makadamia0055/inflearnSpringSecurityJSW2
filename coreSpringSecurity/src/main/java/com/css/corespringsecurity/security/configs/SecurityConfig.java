package com.css.corespringsecurity.security.configs;

import com.css.corespringsecurity.security.provider.CustomAuthenticationProvider;
import com.css.corespringsecurity.security.service.CustomUserDetailsService;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .authorizeRequests()
                .antMatchers("/", "/users").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
        .and()
                .formLogin();

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

    //강의에서 쓰는 configure가 deprecated 되어서 이전 프로젝트에서 가지고 옴
   /* @Bean
    public static UserDetailsManager users() {

        UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111")
                .roles("USER")
                .build();

        UserDetails sys = User.builder()
                .username("manager")
                .password("{noop}1111")
                .roles("MANAGER", "USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN", "MANAGER", "USER")
                .build();

        return new InMemoryUserDetailsManager( user, sys, admin );
    }*/

   /* @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception{
        return authenticationConfiguration.getAuthenticationManager();

    }*/

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(){
        return new CustomAuthenticationProvider();

    }


}
