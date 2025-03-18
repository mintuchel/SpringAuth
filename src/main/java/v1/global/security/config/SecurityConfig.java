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

    // AuthenticationManager 가 인자로 받을 AuthenticationConfiguration 객체 생성자 주입
    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JwtProvider jwtProvider) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtProvider = jwtProvider;
    }

    // LoginFilterChain(UsernamePasswordAuthenticationFilter)에 필요한 AuthenticationManager 를 @Bean 으로 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }

    // AuthenticationManager 에 필요한 PasswordEncoder @Bean 으로 등록
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // 내가 Security Logic 에 등록하고 싶은 새로운 하나의 customFilterChain 에 대한 정의
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

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

        http
                .csrf((auth) -> auth.disable());
        http
                .formLogin((auth) -> auth.disable());
        http
                .httpBasic((auth) -> auth.disable());

        http
                .authorizeHttpRequests((auth) -> auth
                        // 해당 URL 은 모두 허용
                        .requestMatchers("/login", "/", "/join").permitAll()
                        // /admin URL 은 ADMIN 인 ROLE 만 허용
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        http
                .addFilterBefore(new JwtFilter(jwtProvider), LoginFilter.class);

        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtProvider), UsernamePasswordAuthenticationFilter.class);

        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
