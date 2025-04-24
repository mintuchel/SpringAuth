package v1.domain.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import v1.global.security.model.JwtUserDetails;

@RestController
public class MyPageController {
    @GetMapping("/mypage")
    public String handleMyPage(@AuthenticationPrincipal JwtUserDetails userDetails){
        System.out.println("current user");
        System.out.println("id :" + userDetails.getId());
        System.out.println("username : " + userDetails.getUsername());
        System.out.println("password : " + userDetails.getPassword());
        System.out.println("authorities : " + userDetails.getAuthorities());
        return "MyPageController";
    }
}
