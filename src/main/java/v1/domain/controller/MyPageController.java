package v1.domain.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyPageController {
    @GetMapping("/mypage")
    public String handleMyPage(){
        return "MyPageController";
    }
}
