package v1.global.security.filters;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import v1.domain.dto.JwtUserDetails;
import v1.domain.entity.User;
import v1.global.jwt.JwtProvider;

import java.io.IOException;
import java.util.Date;

/**
 * JwtFilter 는 기존 Jwt 를 검증하는 필터 → 로그인 이후의 요청을 처리
 * JWT 를 담아 보내는 Request 를 Spring Context 내부로 들어가기 전에
 * Servlet 단에서 낚아채 검증하기 위해 커스텀 필터를 생성한다
 * 이 필터는 Request 들을 낚아채서 Jwt 토큰 여부 및 유효성을 검증함
 *
 * JwtFilter 는 클라이언트가 이미 Jwt 를 가지고 있을때 실행되는 필터임!
 * 1) 클라이언트가 이미 가지고 있는 Jwt 를 검증하는 역할
 * 2) 검증이 성공하면 Spring Security 의 SecurityContext 에 인증 정보 저장
 */
public class JwtFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    public JwtFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Request Header 에서 Authorization 을 찾음
        String authorization = request.getHeader("Authorization");

        if(authorization != null) {
            System.out.println("Request doesnt have 'Authorization'");
            return;
        }

        if(!authorization.startsWith("Bearer ")) {
            System.out.println("Request doesnt have bearer token");
            return;
        }

        // Bearer 부분 제거한 순수 Jwt 추출
        // authorization.split("")[1];
        String token = authorization.substring(7);

        /**
         * 우리쪽에서 발급한 토큰이 맞는지 확인
         * 맞으면 Payload 의 Claims 값 반환
         * 아니면 내부에서 예외 터짐!
         */
        Claims claims = jwtProvider.verifySignature(token);

        // 만료시간 추출
        Date expirationDate = claims.getExpiration();

        // 만료된 토큰이면
        if(expirationDate.before(new Date())) {
            System.out.println("Token is expired");
            filterChain.doFilter(request, response);
            return;
        }

        // Claim 들 추출
        String username = claims.get("username", String.class);
        String role = claims.get("role", String.class);

        User user = new User();
        user.setUsername(username);
        user.setPassword("temppassword");
        user.setRole(role);

        // Spring Security 는 UserDetails 타입의 객체를 사용해 인증을 처리함
        // Spring Security 에서 인증 객체를 만들려면 UserDetails 를 구현한 객체가 필요
        JwtUserDetails jwtUserDetails = new JwtUserDetails(user);

        // SecurityContext 에 저장할 Authentication 객체 생성
        // UsernamePasswordAuthenticationToken 은 Authentication 을 구현한 객체
        Authentication authToken = new UsernamePasswordAuthenticationToken(jwtUserDetails, null, jwtUserDetails.getAuthorities());

        /**
         * Spring Security 는 SecurityContextHolder 에 있는 Authentication 객체를 기반으로 인증을 수행
         * 이 필터를 통과한 이후 Spring Security 의 다른 필터나 컨트롤러에서
         * SecurityContextHolder.getContext().getAuthentication()을 호출하면 현재 로그인한 사용자 정보를 가져올 수 있음
         */
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // filterChain 에 등록된 다음 필터한테 request response 넘기기
        filterChain.doFilter(request, response);
    }
}

// 짧지만 가독성은 더 안좋은 코드
//
//        // 해당 토큰이 우리쪽에서 발급한 토큰이 맞고, 유효기간이 만료되지 않았으면
//        // isExpired 함수 과정 상 verifySignature 함수가 호출되므로 유효성 검증이 포함되어 있음
//        if(jwtUtil.isExpired(token)) {
//            System.out.println("Token is expired");
//            filterChain.doFilter(request, response);
//
//            return;
//        }
//
//        String username = jwtUtil.getUsername(token);
//        String role = jwtUtil.getRole(token);
//
//        UserEntity userEntity = new UserEntity();
//        userEntity.setUsername(username);
//        userEntity.setPassword("temppassword");
//        userEntity.setRole(role);
//
//        // UserDetails 객체에 회원 정보 객체 담기
//        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);
//
//        // Authentication 객체로 만들고
//        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
//
//        // SecurityContext 에 저장해두기
//        // 이러면 이 필터 뒤에 있는 LoginFilter 에서 해당 Authentication Token 을 AuthenticationManager 에게 넘겨서 인증을 진행함!!
//        SecurityContextHolder.getContext().setAuthentication(authToken);
//
//        filterChain.doFilter(request, response);