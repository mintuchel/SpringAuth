package v1.domain.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import v1.domain.dto.JwtUserDetails;

@RestController
public class UserInfoController {
    @GetMapping("/user-info")
    public String userInfoProcess(@AuthenticationPrincipal JwtUserDetails jwtUserDetails){
        String name = SecurityContextHolder.getContext().getAuthentication().getName();

        System.out.println("Reached UserInfoController");
        System.out.println("Authentication Token found");
        System.out.println("Token Owner : " + name);

        return "userInfo success";
    }
}
