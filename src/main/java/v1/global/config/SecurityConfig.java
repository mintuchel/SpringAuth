package v1.global.config;

import v1.global.jwt.JWTUtil;
import v1.global.jwt.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity // 이게 뭔 뜻??
public class SecurityConfig {

    // AuthenticationManager가 인자로 받을 AuthenticationConfiguration
    private final AuthenticationConfiguration authenticationConfiguration;

    // SecurityConfig에서 Filter에 JWTUtil 주입
    private final JWTUtil jwtUtil;

    // 위에꺼 생성자로 주입
    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil){
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    // security를 통해서 회원 정보를 저장하거나 회우너가입, 검증할때는 항상 비번을 캐시로 암호화시켜서 검증하게됨
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // LoginFilter 생성자의 매개변수로 전달해야하는 AuthenticationManager를 빈으로 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        // Cross-Site Request Forgery 공격 방어 기능을 비활성화
        // REST API나 JWT 토큰 기반 인증에서는 보통 서버가 세션을 사용하지 않기 때문에 CSRF가 불필요할때가 많음
        http.csrf((auth) -> auth.disable());
        // Form 로그인 방식 disable
        // 이 설정은 클라이언트에서 별도의 로그인 페이지를 사용하거나 다른 인증 방식을 사용할때 필요함
        http.formLogin((auth) -> auth.disable());
        // HTTP 기본 인증 방식 비활성화
        // 브라우저에서 기본적으로 제공하는 팝업 창을 통해 사용자 인증을 처리하는 방식인데,
        // JWT나 OAuth 같은 다른 인증 방식을 사용하기 위해 비활성화한 것입니다.
        http.httpBasic((auth) -> auth.disable());

        // 특정 URL 경로에 대한 접근 권한 설정
        http.authorizeHttpRequests((auth) -> auth
                        // login join은 모든 사용자들에게 허용된 경로
                        .requestMatchers("/login","/","/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        // 커스텀 로그인 필터인 LoginFilter 추가
        // Spring Security의 기본 필터 체인에서 UsernamePasswordAuthenticationFilter 위치에 추가함
        // 이 필터가 JWT 기반 인증을 처리하고
        // 클라이언트에서 제공한 JWT 토큰을 검증하거나 발급하는 역할을 함
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 세션 설정
        // jwt는 세션을 항상 stateless로 관리
        // 이 부분이 가장 중요함!
        http.sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // http.build를 통해 SecurityFilterChain 객체를 반환
        // 이 객체는 HTTP 요청과 관련된 모든 보안 설정을 담고 있고
        // Spring Security에서 요청을 처리할때 이 설정을 기준으로 동작함
        return http.build();
    }
}
