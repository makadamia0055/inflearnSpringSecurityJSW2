package com.css.corespringsecurity.controller.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping(value="/messages")
    public String mypage() throws Exception{

        return "user/messages";
    }

    @GetMapping("/api/messages")
    @ResponseBody // json형식으로 보내야하기 때문에
    public String apiMessages(){
        return "messages ok";
    }
}
