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

// ��û ���� Ŭ����, Security�� ������ �̿��Ͽ� ���������� jwt ������� �����Ϸ��� ���� Ŭ������ ����� �����
@Component
public class JWTTokenFilter extends GenericFilterBean {
	
	private JWTTokenProvider provider;
	
	public JWTTokenFilter(JWTTokenProvider provider) {
		this.provider = provider;
	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		String token = ((HttpServletRequest) request).getHeader(JWTTokenProvider.HTTPHeaderKey);
		
		// ��ȿ ��ū üũ
		if (token != null && provider.TokenCheck(token)) {
			// ��ȿ ��ū�̸� ��ū���κ��� ���� ������ �޾ƿ�
			Authentication authentication = provider.PermissionInquery(token);
			//Security�� authentication ��ü ����
			SecurityContextHolder.getContext().setAuthentication(authentication);
			System.out.println(authentication);
		}
		chain.doFilter(request, response);
	}
}