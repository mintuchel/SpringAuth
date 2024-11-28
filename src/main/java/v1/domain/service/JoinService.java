package v1.domain.service;

import v1.domain.dto.JoinDTO;
import v1.domain.entity.UserEntity;
import v1.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;

    // password 암호화를 위한 Bean 객체 주입받기
    // 이 Bean 객체는 SecurityConfig 에서 생성한 빈임
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDTO joinDTO){
        String username = joinDTO.username();
        String password = joinDTO.password();

        Boolean doesExist = userRepository.existsByUsername(username);

        if(doesExist) return;

        UserEntity newUser = new UserEntity();
        newUser.setUsername(username);

        // password 는 무조건 암호화해서 넣어줘야함!!
        newUser.setPassword(bCryptPasswordEncoder.encode(password));
        newUser.setRole("ROLE_ADMIN");

        userRepository.save(newUser);
    }
}
