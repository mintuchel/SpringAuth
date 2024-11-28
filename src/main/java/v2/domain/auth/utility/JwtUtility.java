package v2.domain.auth.utility;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

// @Component
public class JwtUtility {
    private final SecretKey key;
    private final Long jwtAccessTokenExpiration;

    // 생성자
    public JwtUtility(@Value("${jwt.secret}")String secret, @Value("${jwt.access_token_expiration}")long jwtAccessTokenExpiration){
        byte[] keyBytes = Encoders.BASE64.encode(secret.getBytes()).getBytes();

        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.jwtAccessTokenExpiration = jwtAccessTokenExpiration;
    }

    // 새로운 JwtToken 발급받기
    public ResponseEntity<?> generateJwtResponse(Map<String, String> claims){
        Date now = new Date();

        String accessToken = Jwts.builder()
                .claims(claims)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + jwtAccessTokenExpiration)).signWith(key)
                .compact();

        HttpHeaders responseHeaders = new HttpHeaders();
        // 넌 여기에 왜 Bearer 안씀??
        responseHeaders.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);

        return ResponseEntity.ok().headers(responseHeaders).build();
    }

    // Token에서 사용자 정보있는 Claim 받아오기
    public Jws<Claims> getClaimsFromToken(String token){
        try {
            return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
        }catch(SecurityException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e){
            throw new RuntimeException();
        }catch(ExpiredJwtException e){
            throw new RuntimeException();
        }
    }
}
