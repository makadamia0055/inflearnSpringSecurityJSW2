package com.css.corespringsecurity.controller.login;

import com.css.corespringsecurity.domain.entity.Account;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

    @RequestMapping(value={"/login", "/api/login"})
    public String login(@RequestParam(value="error", required = false) String error,
                        @RequestParam(value="exception", required = false) String exception, Model model){
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);

        return "user/login/login";
    }
    @GetMapping("/logout")
    public String logout(HttpServletRequest req, HttpServletResponse resp){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication!=null){
            new SecurityContextLogoutHandler().logout(req, resp, authentication);
        }
        return "redirect:/logout";
    }

    @GetMapping(value={"/denied", "/api/denied"})
    public String accessDenied(@RequestParam(value="exception", required = false)String exception, Model model){
        // 유저 이름을 꺼내기 위해 SecurityContextHolder에서 인증객체를 꺼내고, 그 인증 객체에서 미리 설정해둔 Principle 객체를 꺼내 유저네임 추출.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account account =(Account) authentication.getPrincipal();
        // 추출한 유저 네임을 모델로 전달.
        model.addAttribute("username", account.getUsername());
        model.addAttribute("exception", exception);

        return "user/login/denied";

    }
}
