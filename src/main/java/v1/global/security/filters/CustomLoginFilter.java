package v1.global.security.filters;

import v1.domain.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import v1.global.jwt.JwtUtil;

import java.util.Collection;
import java.util.Iterator;

/**
 *  내가 만든 커스텀 필터
 *  UsernamePasswordAuthenticationFilter 는 인증을 진행할때 아이디, 패스워드를 파싱하여 인증요청을 위임하는 필터
 *  Login 을 시도하면 인증을 위한 Token 을 생성한 후 인증을 AuthenticationManager 에 위임함
 *  이 녀석은 SecurityConfig 에 정의되어있는 필터체인에 들어갈 한 개의 커스텀 필터임
 *  이 커스텀 필터를 통해 Jwt 토큰 관리하려는거임
 */

public class CustomLoginFilter extends UsernamePasswordAuthenticationFilter {

    // 검증을 위임할 녀석
    // username과 Password를 파싱한 후 UsernamePasswordAuthenticationToken 이라는 객체로 만들어 얘한테 줄거임
    private final AuthenticationManager authenticationManager;

    // Jwt token 작업을 위임할 녀석
    private final JwtUtil jwtUtil;

    public CustomLoginFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil){
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    // authenticationManager 에게 넘겨 인증
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // client http request 에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("username:" + username + " password:" + password);

        // 여기서 세번째인자인 authorities 는 말그대로 권한임
        // 이건 클라이언트가 직접 보내는게 아님. 서버 측에서 인증 과정 중에 설정되는거임
        // 조회한 사용자 정보에 권한 정보(ROLE_USER, ROLE_ADMIN)를 추후에 추출할 수 있음
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        return authenticationManager.authenticate(authToken);
    }

    // attemptAuthentication 이 성공했다면 이 함수가 실행됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication){
        // 보안 맥락에서 Principal 은 인증된 사용자를 뜻함!
        // 즉 인증된 사용자 정보를 내가 직접 정의한 CustomUserDetails 로 받아오기
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        // username 추출
        String username = customUserDetails.getUsername();

        // authorities 권한 추출
        Collection<? extends GrantedAuthority> authroities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authroities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        // JwtUtil을 통해 토큰 생성하기
        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        // Client 한테 보낼 시에 토큰을 보내줘야하므로
        // 인자로 받은 response 에 token 추가해주기
        // HTTP 인증 방식이라 헤더에 다음과 같이 넣어야함
        // Bearer 인증 방식 하고 띄어쓰기 무조건 해줘야함
        response.addHeader("Authorization", "Bearer " + token);
    }

    // attemptAuthentication 이 실패했다면 이 함수가 실행됨
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed){
        response.setStatus(401);
    }
}
