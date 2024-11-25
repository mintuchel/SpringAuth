package v1.domain.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class AdminController {
    @GetMapping("/admin")
    public String adminP(){
        return "AdminController";
    }
}
