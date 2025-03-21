package v1.domain.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import v1.domain.dto.JwtUserDetails;

@RestController
public class AdminController {
    @GetMapping("/admin")
    public String adminProcess(@AuthenticationPrincipal JwtUserDetails jwtUserDetails){
        String name = SecurityContextHolder.getContext().getAuthentication().getName();

        System.out.println("Reached AdminController");
        System.out.println("Authentication Token found");
        System.out.println("Token Owner : " + name);

        return "admin success";
    }
}
