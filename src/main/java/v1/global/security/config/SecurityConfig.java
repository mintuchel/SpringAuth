package v1.global.security.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import v1.global.jwt.JwtProvider;
import v1.global.security.filters.LoginFilter;
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
import v1.global.security.filters.JwtFilter;

import java.util.Collections;

/**
 * 이 SecurityConfig 파일 안에 SecurityFilter"Chain" 을 반환하는 @Bean 을 정의해둠으로써
 * WAS 톰캣 필터 체인이 아닌! Spring Security 필터체인을 커스텀해서 등록할 수 있음
 * 이 Spring Security 필터체인은 톰캣 필터체인과 달리 스프링 컨테이너 내부에서 동작함!!
**/

@Configuration
@EnableWebSecurity // Spring Security 를 활성화하겠다. 필터 체인을 생성하고 웹 보안을 활성화하겠다
public class SecurityConfig {

    // 내가 Security Logic 에 등록하고 싶은 새로운 하나의 customFilterChain 에 대한 정의
    @Bean
    public SecurityFilterChain customFilterChain(HttpSecurity http) throws Exception{

        http
                .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        // frontend 포트 3000번에서 보내는거 허용
                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        // 모든 http method 허용
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        // Jwt 사용해야하므로 Authorization 헤더 허용해주기
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                })));

        // Cross-Site Request Forgery 공격 방어 기능을 비활성화
        // REST API 나 JWT 토큰 기반 인증에서는 보통 서버가 세션을 사용하지 않기 때문에 CSRF 가 불필요할때가 많음
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
                        .requestMatchers("/","/join","/login").permitAll() // main login join은 모든 사용자들에게 허용된 경로
                        .requestMatchers("/admin").hasRole("ADMIN") // adim 은 ADMIN 롤인 사람만 가능하게끔 허용
                        .anyRequest().authenticated());

        /**
         * Request Header 를 통해 토큰 유효성을 검증해주는 JwtFilter
         *  로그인 인증과 필요시 Jwt Token 발급을 해주는 CustomLoginFilter
         *  이 두 개의 커스텀 필터를 SecurityFilterChain 에 추가하는 작업이 아래 두 줄임
         *  Spring Security 의 Default 필터 체인에서 UsernamePasswordAuthenticationFilter 위치에 추가
         *  이 필터가 JWT 기반 인증을 처리하고 클라이언트에서 제공한 JWT 토큰을 검증하거나 발급하는 역할을 함
         */

        http.addFilterBefore(new JwtFilter(jwtProvider), LoginFilter.class);
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtProvider), UsernamePasswordAuthenticationFilter.class);

        // 세션 설정
        // jwt는 세션을 항상 stateless로 관리
        // 이 부분이 가장 중요함!
        http.sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // http.build 를 통해 SecurityFilterChain 객체를 반환
        // 이 객체는 HTTP 요청과 관련된 모든 보안 설정을 담고 있고
        // Spring Security 에서 요청을 처리할때 위에서 해준 설정을 기준으로 동작함
        return http.build();
    }

    // CustomLoginFilter 에 필요한 AuthenticationManager 를 생성하기 위한 AuthenticationConfiguration 주입받기
    private final AuthenticationConfiguration authenticationConfiguration;

    // CustomLoginFilter 에 필요한 JWTUtil 주입받기
    private final JwtProvider jwtProvider;

    // 위에 생성한 CustomFilterChain 인 loginFilterChain 생성자의 매개변수로 전달해야하는 AuthenticationManager 를 빈으로 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }

    // 위에꺼 생성자로 주입
    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JwtProvider jwtProvider){
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtProvider = jwtProvider;
    }

    // Spring Security 를 통해서 회원 정보를 저장할때는 암호화해서 저장함
    // 이 password 암호화 Bean 은 추후 Service 단에서 해당 Bean 을 주입받아서 쓰게됨
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
