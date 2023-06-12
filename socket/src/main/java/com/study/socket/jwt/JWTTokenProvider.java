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
	
	// HTTP ���Ϳ� ���� Ű ��
	public static String HTTPHeaderKey = "Authorization";
	private Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
	private long KeepTime = 60 * 60 * 1000L;
	
	private final UserDetailsService userService;
	
	public JWTTokenProvider(UserDetailsService userService) {
		this.userService = userService;
	}
	
	// ��ü �ʱ�ȭ, secretKey�� Base64�� ���ڵ�
//	@PostConstruct
//	protected void SecretKeyIncodig() {
//		secretKey = Base64.getEncoder().encodeToString(secretKey);
//	}
	
	// JWT ��ū ����
	public String PublishToken(String userPk, List<String> roles) {
		// jwt payload ���� �ĺ� ��
		Claims claims = Jwts.claims().setSubject(userPk);
		claims.put("roles", roles);
		Date now = new Date();
		
		return Jwts.builder()
				.setClaims(claims) // ��������
				.setIssuedAt(now) // ��ū ���� �ð�
				.setExpiration(new Date(now.getTime() + KeepTime)) // ����ð�
				.signWith(secretKey) // �˰����� Ű��
				.compact();
					
	}
	
	// JWT ��ū���� ���� ���� ��ȸ
	public Authentication PermissionInquery(String token) {
		UserDetails userDetails = userService.loadUserByUsername(this.UserCheck(token));
		return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
	}
	
	// ��ū�� ��ȿ�� + �������� Ȯ��
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
	
	// ��ū���� ȸ�� ���� ����
	private String UserCheck(String token) {
		return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
	}
}