package SpringJWT.JwtTest.service;

import SpringJWT.JwtTest.dto.JoinDTO;
import SpringJWT.JwtTest.entity.User;
import SpringJWT.JwtTest.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    // password 암호화를 위한
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDTO joinDTO){
        String username = joinDTO.username();
        String password = joinDTO.password();

        Boolean isExist = userRepository.existsByUsername(username);

        if(isExist){
            return;
        }

        User newUser = User.builder()
                .username(username)
                // password 는 무조건 암호화를 진행해서 넣어야함!!
                // 바로 .password(password) 하면 안됨!!
                .password(bCryptPasswordEncoder.encode(password))
                .role("ROLE_ADMIN")
                .build();

        userRepository.save(newUser);
    }
}
