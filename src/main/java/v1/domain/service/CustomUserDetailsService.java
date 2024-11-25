package v1.domain.service;

import v1.domain.dto.CustomUserDetails;
import v1.domain.entity.User;
import v1.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// UserDetailService
// SpringSecurity 에서 User의 정보를 가져오는 인터페이스

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // DB 에서 특정 유저를 조회하여 return 해주면 됨
    // 기존 UserDetailsService 인터페이스에서 구현해야하는 놈임
    // return 값은 Spring Security 에서 User 정보 담는 UserDetails 형식
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userData = userRepository.findByUsername(username);

        if(userData!=null){
            return new CustomUserDetails(userData);
        }

        return null;
    }
}
