package v1.domain.service;

import v1.domain.dto.JwtUserDetails;
import v1.domain.entity.User;
import v1.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 필터 단에서 사용되는 Service
 * 필터 단에게 UserDetails 객체로 return 을 해줘야하기 때문에
 * 내부적으로 실제 User 에 대한 정보가 있는 UserRepository 에서 User 를 조회한 뒤,
 * CustomUserDetails 객체 (UserDetails 구현체) 로 변환하여 return 해준다
 */

@Service
@RequiredArgsConstructor
public class JwtUserDetailsService implements UserDetailsService {

    // 실제 User 에 대한 정보를 가져오기 위해 UserRepository 를 참조해야함
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // User 객체 조회하기
        User user = userRepository.findByUsername(username);

        // UserDetails 객체로 반환
        if(user !=null){
            return new JwtUserDetails(user);
        }

        // 존재하지 않으면 null 반환
        return null;
    }
}
