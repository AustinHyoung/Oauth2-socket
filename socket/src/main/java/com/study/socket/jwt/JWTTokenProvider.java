package com.study.socket.jwt;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;

@Component
public class JWTTokenProvider {
	
	// HTTP 헤터에 담을 키 값
	public static String HTTPHeaderKey = "Authorization";
	private Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
	private long KeepTime = 60 * 60 * 1000L;
	
	private final UserDetailsService userService;
	
	public JWTTokenProvider(UserDetailsService userService) {
		this.userService = userService;
	}
	
	// 객체 초기화, secretKey를 Base64로 인코딩
//	@PostConstruct
//	protected void SecretKeyIncodig() {
//		secretKey = Base64.getEncoder().encodeToString(secretKey);
//	}
	
	// JWT 토큰 생성
	public String PublishToken(String userPk, List<String> roles) {
		// jwt payload 유저 식별 값
		Claims claims = Jwts.claims().setSubject(userPk);
		claims.put("roles", roles);
		Date now = new Date();
		
		return Jwts.builder()
				.setClaims(claims) // 정보저장
				.setIssuedAt(now) // 토큰 발행 시간
				.setExpiration(new Date(now.getTime() + KeepTime)) // 만료시간
				.signWith(secretKey) // 알고리즘 키값
				.compact();
					
	}
	
	// JWT 토큰에서 인증 정보 조회
	public Authentication PermissionInquery(String token) {
		UserDetails userDetails = userService.loadUserByUsername(this.UserCheck(token));
		return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
	}
	
	// 토큰의 유효성 + 만료일자 확인
	public boolean TokenCheck(String jwtToken) {
		try {
			Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(jwtToken);
			System.out.println(claims);
			return !claims.getBody().getExpiration().before(new Date());
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}
	
	// 토큰에서 회원 정보 추출
	private String UserCheck(String token) {
		return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
	}
}
