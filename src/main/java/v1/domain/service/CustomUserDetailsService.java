package v1.domain.service;

import v1.domain.dto.CustomUserDetails;
import v1.domain.entity.UserEntity;
import v1.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


/**
 * implements UserDetailsService
 * Spring Security 에서 User의 정보를 가져오는 인터페이스
 * 그래서 UserRepository 를 사용하는거임
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * DB 에서 특정 유저를 조회하여 return 해주면 됨
     * 구현해줘야하는 놈임
     * Spring Security 에서 사용하는 스펙인 UserDetails 객체로 return 해줘야함!
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntityData = userRepository.findByUsername(username);

        if(userEntityData !=null){
            return new CustomUserDetails(userEntityData);
        }

        return null;
    }
}
