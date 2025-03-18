package v1.global.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletInputStream;
import org.springframework.util.StreamUtils;
import v1.domain.dto.JwtUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import v1.domain.dto.LoginDTO;
import v1.global.jwt.JwtProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Iterator;

/**
 *   LoginFilter 는 로그인할 때 새 Jwt 를 생성하는 필터 → 로그인 시에만 실행
 *  사용자가 로그인할 때 새로운 Jwt 를 발급하는 역할
 *  로그인 요청을 처리하고, 인증이 성공하면 새로운 Jwt 를 생성
 *  클라이언트는 이 새 Jwt 를 받아서 이후 요청마다 Authorization 헤더에 넣어 사용
 */

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    // 내부적으로 UserDetailsService 구현체와 PasswordEncoder 를 사용해 검증 진행
    // 모두 Bean 으로 등록되어 있어 자동 주입
    private final AuthenticationManager authenticationManager;

    // 로그인 성공 시 Jwt 생성을 위해
    private final JwtProvider jwtProvider;

    public LoginFilter(AuthenticationManager authenticationManager, JwtProvider jwtProvider){
        this.authenticationManager = authenticationManager;
        this.jwtProvider = jwtProvider;
    }

    // 로그인 시도
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // multipart/form-data 로 받을때 사용
        // String username = obtainUsername(request);
        // String password = obtainPassword(request);

        // JSON 형식으로 받기
        LoginDTO loginDTO = new LoginDTO();

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            ServletInputStream inputStream = request.getInputStream();
            String messageBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
            loginDTO = objectMapper.readValue(messageBody, LoginDTO.class);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String username = loginDTO.getUsername();
        String password = loginDTO.getPassword();

        System.out.println("username:" + username + " password:" + password);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // UserDetailsService 를 통해 아이디 비번 일치 여부 확인
        // 확인 시 Authentication 객체 만들어 반환
        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공 (Jwt 를 여기서 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication){
        JwtUserDetails jwtUserDetails = (JwtUserDetails) authentication.getPrincipal();

        String username = jwtUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        String token = jwtProvider.createJwt(username, role, 60*60*10L);

        // Bearer 인증 방식 하고 띄어쓰기 무조건 해줘야함
        response.addHeader("Authorization", "Bearer " + token);
    }

    // 로그인 실패
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed){
        response.setStatus(401);
    }
}
