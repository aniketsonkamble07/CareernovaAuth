package com.careernova.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HomeController {

    @GetMapping("/")
    public String index(
            @RequestParam(required = false) String token,
            @RequestParam(required = false) String error,
            Model model
    ) {
        if (token != null) {
            model.addAttribute("token", token);
            model.addAttribute("message", "Login successful!");
            model.addAttribute("messageClass", "success");
        }

        if (error != null) {
            model.addAttribute("error", error);
        }

        return "forward:/index.html"; // Serves static/index.html
    }

    @GetMapping("/login")
    public String login() {
        return "redirect:/";
    }
}