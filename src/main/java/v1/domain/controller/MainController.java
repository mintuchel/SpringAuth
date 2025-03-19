package v1.domain.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {
    @GetMapping("/")
    public String mainProcess(){
        String name = SecurityContextHolder.getContext().getAuthentication().getName();

        System.out.println("Reached MainController");
        System.out.println("Authentication Token found");
        System.out.println("Token Owner : " + name);

        return "main success";
    }
}
