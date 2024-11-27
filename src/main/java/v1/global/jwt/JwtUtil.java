package v1.global.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

// JWT 를 생성하고 검증하고 만드는 Util 클래스

@Component
public class JwtUtil {
    // 객체 키 클래스가 있음
    private SecretKey secretKey;

    // 객체 키로 변환시켜줘야함
    public JwtUtil(@Value("${spring.jwt.secret}") String secret){
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // ================================= JWT TOKEN 생성 =================================

    public String createJwt(String username, String role, Long expiredMs){
        return Jwts.builder()
                .claim("username",username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) // 현재 발행 시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // Token 소멸 시간
                .signWith(secretKey)
                .compact();
    }

    // ============================= JWT TOKEN 파싱 확인 작업 =============================

    // Jwts.parser().verifyWith(secretKey) = 우리 쪽에서 발급한 토큰이 맞는지 확인
    // 여기서부터는 특정 요소를 검증하기 위해 token을 파싱하는 작업

    public String getUsername(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role",String.class);
    }

    // 소멸되었으면 true
    // 소멸되지 않았으면 false
    public Boolean isExpired(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }
}
