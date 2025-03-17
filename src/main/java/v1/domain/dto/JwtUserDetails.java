package v1.domain.dto;

import v1.domain.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

// UserDetails Interface 를 구현
// 내부에 있는 함수들 모두 @Override
// Spring Security 에서 사용자 정보 담는 인터페이스

// 실제 유저들을 저장하는 User 엔티티를 감싸고 있음

// 내부의 User 객체를 초기화할 수 있는 생성자가 필요하므로 @RequiredArgsConstructor 선언
@RequiredArgsConstructor
public class JwtUserDetails implements UserDetails {

    private final User user;

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired(){
        return true;
    }

    @Override
    public boolean isAccountNonLocked(){ return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });

        return collection;
    }
}
