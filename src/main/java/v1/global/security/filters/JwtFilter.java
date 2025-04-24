package v1.global.security.filters;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import v1.global.security.model.JwtUserDetails;
import v1.global.security.jwt.JwtUtil;

import java.io.IOException;

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

    private final JwtUtil jwtUtil;

    public JwtFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        System.out.println("========== [ JwtFilter executed ] ==========");

        // Request Header 에서 Jwt 추출
        String accessToken = getAccessToken(request);

        // accessToken 이 존재하지 않는다면
        if (accessToken == null) {

            System.out.println("token null");
            // filterChain 내 다음 필터 수행
            filterChain.doFilter(request, response);
            return;
        }else{
            System.out.println("token exists");
        }

        /**
         * 우리쪽에서 발급한 토큰이 맞는지 확인
         * 맞으면 Payload 의 Claims 값 반환
         * 아니면 내부에서 예외 터짐!
         */
        Claims claims;
        try {
            claims = jwtUtil.verifySignature(accessToken);
        } catch(JwtException e) {
            System.out.println("invalid token!" + " ( " + e.getMessage() + " )");
            return;
        }

        System.out.println("existing token is valid!");

        // 만약 만료기간 지났다면
        if(jwtUtil.isExpired(claims)) {
            System.out.println("token is expired!");
            // 다음 필터인 LoginFilter 로 진행
            filterChain.doFilter(request, response);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid JWT Token!");
            return;
        }else{
            System.out.println("token is not expired!");
        }

        // Spring Security 는 UserDetails 타입의 객체를 사용해 인증을 처리함
        // Spring Security 에서 인증 객체를 만들려면 UserDetails 를 구현한 객체가 필요
        JwtUserDetails jwtUserDetails = new JwtUserDetails(jwtUtil.getUsername(claims), jwtUtil.getRole(claims));

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

    private String getAccessToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");

        if(authorization == null) {
            System.out.println("request doesnt have 'Authorization'");
            return null;
        }

        if(!authorization.startsWith("Bearer ")) {
            System.out.println("request doesnt have bearer token");
            return null;
        }

        // Bearer 부분 제거한 순수 Jwt 추출
        return authorization.substring(7);
    }
}