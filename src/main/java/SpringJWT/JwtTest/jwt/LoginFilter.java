package SpringJWT.JwtTest.jwt;

import SpringJWT.JwtTest.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;

// 로그인을 하는 부분은 LoginFilter에서 진행하고
// JWT 토큰을 발급해주는 곳은 JWTUtil 클래스에서 진행함
// 그래서 이거 두개가 묶여서 로그인이 진행되는거임!

// @PostMapping("/login")이 있어도 필더단에서 요청을 처리하여 응답하기 때문에 컨트롤러로 응답이 가지 않음
// Spring Security가 동작하는 위치는 Filter임!
// 클라이언트 요청 -> 필터들 -> 서블릿(컨트롤러)
// 필터 자체에서 Servlet으로 보내지 않고, 성공/실패가 발생하며 로그인 요청에 대한 특정 응답을 보내고 싶으면 필터에
// 커스텀을 진행해야함

// 이렇게 만든 필터를 등록을 해줘야함
// SecurityConfig 인 설정정보에 등록해주면 됨

// UsernamePasswordAuthenticationFilter는 인증을 진행할때 아이디, 패스워드를 파싱하여 인증 요청을 위임하는 필터
// Login을 시도하면 인증을 위한 Token을 생성 한 후 인증을 다른 쪽에 위임하는 역할을 하는 필터
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    // 검증을 위임할 녀석
    // Filter 는 id, pw를 추출하여 토큰으로 만들어 얘한테 검증이라는 행위를 위임함
    private final AuthenticationManager authenticationManager;

    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil){
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    // authenticationManager 에게 넘겨 인증
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 클라이언트 요청에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println(username);

        // 꺼낸 값을 이용하여 인증을 진행
        // Authentication Filter가 Authentication Manager라는 친구에게 username, password를 던져줘서 인증을 받을건데
        // 이때 내부적으로 DTO처럼 만들어서 보내줌
        // 그 바구니가 이거임
        // 여기서 authroities 는 ??
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        return authenticationManager.authenticate(authToken);
    }

    // 로그인이 성공하면 토큰을 만들어줘야함
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication){
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authroities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authroities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        // Bearer 인증 방식 하고 띄어쓰기 무조건 해줘야함
        // HTTP 인증 방식이라 헤더에 다음과 같이 넣어야함
        response.addHeader("Authorization", "Bearer " + token);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed){
        response.setStatus(401);
    }
}
