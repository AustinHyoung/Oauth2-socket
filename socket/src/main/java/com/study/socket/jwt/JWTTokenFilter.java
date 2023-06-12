package com.study.socket.jwt;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

// 요청 검증 클래스, Security는 세션을 이용하여 검증하지만 jwt 방식으로 변경하려면 필터 클래스를 만들어 줘야함
@Component
public class JWTTokenFilter extends GenericFilterBean {
	
	private JWTTokenProvider provider;
	
	public JWTTokenFilter(JWTTokenProvider provider) {
		this.provider = provider;
	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		String token = ((HttpServletRequest) request).getHeader(JWTTokenProvider.HTTPHeaderKey);
		
		// 유효 토큰 체크
		if (token != null && provider.TokenCheck(token)) {
			// 유효 토큰이면 토큰으로부터 유저 정보를 받아옴
			Authentication authentication = provider.PermissionInquery(token);
			//Security에 authentication 객체 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
			System.out.println(authentication);
		}
		chain.doFilter(request, response);
	}
}
