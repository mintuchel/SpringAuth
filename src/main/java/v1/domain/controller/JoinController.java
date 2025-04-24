package v1.domain.controller;

import v1.domain.dto.JoinDTO;
import v1.domain.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String handleJoin(JoinDTO joinDTO){
        joinService.joinProcess(joinDTO);
        return "Join Success";
    }
}
