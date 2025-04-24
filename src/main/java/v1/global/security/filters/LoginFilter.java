package v1.global.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletInputStream;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StreamUtils;
import v1.global.security.model.JwtUserDetails;
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
import v1.global.security.jwt.JwtUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Iterator;

/**
 *  LoginFilter 는 로그인할 때 새 Jwt 를 생성하는 필터 → 로그인 시에만 실행
 *  사용자가 로그인할 때 새로운 Jwt 를 발급하는 역할
 *  로그인 요청을 처리하고, 인증이 성공하면 새로운 Jwt 를 생성
 *  클라이언트는 이 새 Jwt 를 받아서 이후 요청마다 Authorization 헤더에 넣어 사용
 */

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    // 내부적으로 UserDetailsService 구현체와 PasswordEncoder 를 사용해 검증 진행
    // 모두 Bean 으로 등록되어 있어 자동 주입
    private final AuthenticationManager authenticationManager;

    // 로그인 성공 시 Jwt 생성을 위해
    private final JwtUtil jwtUtil;

    /**
     * LoginFilter 는 "/login" POST 요청일때만 실행되게 되어있음
     * UsernamePasswordAuthenticationFilter 생성자를 보면 AntPathRequestMatcher("/login", "POST"); 이거를 통해서 작동할 URI 를 명시하고 있음
     * 상속 시에는 생성자 호출 시 부모클래스의 기본생성자가 가장 먼저 호출되므로 아래 생성자에서 super()가 생략되어있다고 보면 됨!
     */
    public LoginFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        // super 기본생성자는 사실 생략해도 자동으로 호출됨!
        super();
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    /**
     * 로그인 시도
     * Authentication 인터페이스를 구현한 UsernamePasswordAuthenticationToken 을 반환
     * authenticationManager.authenticate(authToken); -> 이 함수의 호출 흐름을 간략하게 알고 있으면 좋음
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        System.out.println("========== [ LoginFilter executed ] ==========");

        // JSON 형식으로 받기
        LoginDTO loginDTO;

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

        System.out.println("login success");
        System.out.println("username:" + username + " password:" + password);

        // 이 시점의 authToken.isAuthenticated() 는 false임
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // 이 함수 호출 흐름에서 내부적으로 UserDetailsService 와 PasswordEncoder를 써서 유저 검증을 하고
        // 인증된 객체를 새로 만들어서 리턴해줌
        // 인증이 제대로 되었다면 isAuthenticated() 는 true임
        return authenticationManager.authenticate(authToken);
    }

    /**
     * 로그인 성공 (Jwt 를 여기서 발급하면 됨)
     * 위의 attemptAuthentication 에서 return 한 UsernamePasswordAuthenticationToken 을 인자로 받아
     * 사용자 정보를 추출하고 Jwt 를 생성함
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication){
        JwtUserDetails jwtUserDetails = (JwtUserDetails) authentication.getPrincipal();

        String username = jwtUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        // Jwt 5분으로 설정
        String token = jwtUtil.createJwt(username, role, 5 * 60 * 1000L);

        // Bearer 인증 방식 하고 띄어쓰기 무조건 해줘야함
        response.addHeader("Authorization", "Bearer " + token);
    }

    /**
     * 로그인 실패
     * 단순히 401 응답보내고 끝
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed){
        response.setStatus(401);
    }
}
