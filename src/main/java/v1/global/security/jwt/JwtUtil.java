package v1.global.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

// JWT 생성, 유효성 판단, Claim 추출을 해주는 Component

@Component
public class JwtUtil {

    // 서버 내부 SecretKey
    private final SecretKey secretKey;

    // secret 을 해시알고리즘을 통해 변환하고 final key 로 설정해주기
    public JwtUtil(@Value("${spring.jwt.secret}") String secret){
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // Jwt 생성
    public String createJwt(String email, String username, Long expiredMs){
        return Jwts.builder()

                // Payload 에 원하는 Claim 정보 넣기
                // claim 은 디코딩이 언제나 가능하기 때문에 민감한 정보를 넣으면 안됨!
                .claim("email", email)
                .claim("username", username)

                // Payload 에 발행시간 및 만료시간 추가
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))

                // 인코딩된 헤더와 클레임 부분을 SecretKey 와 서명 알고리즘을 이용해 서명을 생성하여 추가
                .signWith(secretKey)

                // Header, Payload, Signature 를 "." 으로 연결시켜 jwt 토큰 완성
                .compact();
    }

    /**
     * 우리 쪽에서 발급한 토큰이 맞는지 확인
     * Request 로 넘어온 Jwt 의 header 와 payload 부분을 직접 서버의 secret key 로 서명을 생성해본다
     * 현장에서 생성된 서명과 request 로 날아온 서명이 일치하면 우리쪽에서 발급한 토큰이 맞는 것이다!
     * 맞으면 Payload 내부의 Claim 정보들 반환
     * 틀리면 예외 반환
     */
    public Claims verifySignature(String token) {
        return Jwts.parser()
                .verifyWith(secretKey) // 서명 검증 수행
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String getEmail(Claims claims){
        return claims.get("email", String.class);
    }

    // Claim 에서 username 추출
    public String getUsername(Claims claims){
        return claims.get("username", String.class);
    }

    public String getRole(Claims claims){
        return claims.get("role", String.class);
    }

    // Claim 에서 만료기간 확인
    public Boolean isExpired(Claims claims){
        return claims.getExpiration().before(new Date());
    }
}
