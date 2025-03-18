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
 * @Configuration -> 해당 클래스가 설정 클래스임을 Spring 에게 알림
 * 내부의 @Bean 메서드들이 Spring 컨테이너에 등록됨
 *
 * @EnableWebSecurity -> Spring Security 활성화
 * 기본적인 Spring Security 필터 체인이 등록되고 커스텀할 수 있게 해줌
 */

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // AuthenticationManager에 필요한 AuthenticationConfiguration 정의
    private final AuthenticationConfiguration authenticationConfiguration;

    private final JwtProvider jwtProvider;

    // LoginFilterChain(UsernamePasswordAuthenticationFilter)에 필요한 AuthenticationManager 를 @Bean 으로 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JwtProvider jwtProvider){
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtProvider = jwtProvider;
    }

    // AuthenticationManager 에 필요한 PasswordEncoder @Bean 으로 등록
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

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


        http.csrf((auth) -> auth.disable());

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
         * JwtFilter 와 LoginFilter 를 SecurityFilterChain 에 추가
         */
        http.addFilterBefore(new JwtFilter(jwtProvider), LoginFilter.class);
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtProvider), UsernamePasswordAuthenticationFilter.class);

        // 세션 설정
        // Jwt 는 당연히 stateless로 관리
        // 이 부분이 가장 중요함!
        http.sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
