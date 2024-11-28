package v2.domain.auth.filter;

import v2.domain.auth.utility.JwtUtility;
import v2.global.response.GeneralResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

//@Component
public class JwtFilter extends OncePerRequestFilter {
    private final JwtUtility jwtUtility;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtFilter(JwtUtility jwtUtility) {
        this.jwtUtility = jwtUtility;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // accessToken 추출
        String accessToken = resolveToken(request, response);

        // 예외 터졌으면 여기서 종료
        if(accessToken == null) {
            return;
        }

        try{
            // 사용자 정보 추출
            Jws<Claims> claims = jwtUtility.getClaimsFromToken(accessToken);

            // email 추출
            // 근데 넌 왜 email로 함?? id pw 아니고
            String email = claims.getPayload().get("email", String.class);
            System.out.println(email);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(email, null, Collections.emptyList());

            SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request, response);

        }catch(RuntimeException e){
            resolveException(GeneralResponse.INVALID_JWT_TOKEN, response);
        }
    }

    // TokenHandler
    // Client가 보내준 Request Header 까서 jwt access token 확인하기
    // 틀리면 Exception 만들어서 반환
    private String resolveToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String accessToken = request.getHeader("Authorization");

        if(accessToken == null){
            resolveException(GeneralResponse.NO_JWT_TOKEN, response);
            return null;
        }

        if(!accessToken.startsWith("Bearer ")){
            resolveException(GeneralResponse.INVALID_JWT_TOKEN, response);
            return null;
        }

        // 이거 왜 한거??
        return accessToken.substring(7);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getServletPath().equals("/")
                || request.getServletPath().equals("/oauth")
                || request.getServletPath().equals("/health")
                || request.getServletPath().equals("/recipes/options")
                || request.getServletPath().equals("/recipes/generate")
                || request.getServletPath().startsWith("/v3/api-docs")
                || request.getServletPath().startsWith("/swagger-ui");
    }

    // ExceptionHandler
    // 예외가 터지면 Exception 생성해서 반환함
    private void resolveException(GeneralResponse generalResponse, HttpServletResponse response) throws IOException {
        response.setStatus(generalResponse.getCode());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String jsonResponse = objectMapper.writeValueAsString(generalResponse);
        response.getWriter().write(jsonResponse);
    }
}
