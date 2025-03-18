package v1.domain.dto;

import v1.domain.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

/**
 * UserDetails Interface 를 구현
 *
 * Spring Security 에서 사용자 정보를 담는 DTO 형식인 UserDetails Interface 를 구현
 * 실제 유저들을 저장하는 User 엔티티를 감싸고 있음
 */

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
