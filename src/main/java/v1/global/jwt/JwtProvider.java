package v1.global.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

// JWT 생성 및 정보 추출해주는 Utility 클래스

@Component
public class JwtProvider {
    // 객체 키 클래스가 있음
    private final SecretKey secretKey;

    // secret 을 해시알고리즘을 통해 변환하고 final key 로 설정해주기
    public JwtProvider(@Value("${spring.jwt.secret}") String secret){
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // Jwt 생성
    public String createJwt(String username, String role, Long expiredMs){
        return Jwts.builder()
                .claim("username",username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) // 현재 발행 시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // Token 소멸 시간
                .signWith(secretKey)
                .compact();
    }

    // Jwts.parser().verifyWith(secretKey) = 우리 쪽에서 발급한 토큰이 맞는지 확인

    public String getUsername(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role",String.class);
    }

    // Jwt Token 소멸 확인
    public Boolean isExpired(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }
}
