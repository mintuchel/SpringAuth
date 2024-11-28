package v1.global.security.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import v1.domain.dto.CustomUserDetails;
import v1.domain.entity.UserEntity;
import v1.global.jwt.JwtUtil;

import java.io.IOException;

/**
 * 이미 Jwt token 을 발급받아 request 에 담아 보내고 있는 사람들을 위해서
 * 요청에 담긴 JWT 를 검증하기 위한 커스텀 필터를 등록해야 한다.
 * 얘가 검증을 "진행"하지는 않는다. AuthenticationManager를 주입 안받고 있는거로 유추가 가능
 *
 * 얘가 SpringContext 에 Authentication 객체로 박아두면
 * 얘 뒤에 오는 LoginFilter 에서 AuthenticationManager 에게 Authentication 객체를 넘김으로써 실제 검증을 진행함!
 */

public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // request header 에서 Authorization 을 찾음
        String authorization = request.getHeader("Authorization");

        if(authorization != null) {
            System.out.println("Request doesnt have 'Authorization'");
            return;
        }
        if(!authorization.startsWith("Bearer ")) {
            System.out.println("Request doesnt have bearer token");
            return;
        }

        // Bearer 부분 제거한 순수 jwt token 값 추출
        String token = authorization.substring(7); // authorization.split("")[1];

        if(jwtUtil.isExpired(token)) {
            System.out.println("Token is expired");
            filterChain.doFilter(request, response);

            return;
        }

        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword");
        userEntity.setRole(role);

        // UserDetails 객체에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // Authentication 객체로 만들고
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // SecurityContext 에 저장해두기
        // 이러면 이 필터 뒤에 있는 LoginFilter 에서 해당 Authentication Token 을 AuthenticationManager 에게 넘겨서 인증을 진행함!!
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
