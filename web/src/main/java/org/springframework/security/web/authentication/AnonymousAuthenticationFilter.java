/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Detects if there is no {@code Authentication} object in the
 * {@code SecurityContextHolder}, and populates it with one if needed.
 *
 * AnonymousAuthenticationFilter ，用于前面所有filter都认证失败的情况下，自动创建一个默认的匿名用户，拥有匿名访问权限
 *
 * @author Ben Alex
 * @author Luke Taylor
 * 匿名身份过滤器，这个过滤器个人认为很重要，需要将它与UsernamePasswordAuthenticationFilter 放在一起比较理解，spring security为了兼容未登录的访问，也走了一套认证流程，只不过是一个匿名的身份。
 */
public class AnonymousAuthenticationFilter extends GenericFilterBean implements InitializingBean {

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private String key;

	private Object principal;

	private List<GrantedAuthority> authorities;

	/**
	 * Creates a filter with a principal named "anonymousUser" and the single authority
	 * "ROLE_ANONYMOUS".
	 * @param key the key to identify tokens created by this filter
	 * 自动创建一个"anonymousUser"的匿名用户,其具有ANONYMOUS角色
	 */
	public AnonymousAuthenticationFilter(String key) {
		this(key, "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	}

	/**
	 * @param key key the key to identify tokens created by this filter key用来识别该过滤器创建的身份
	 * @param principal the principal which will be used to represent anonymous users principal代表匿名用户的身份
	 * @param authorities the authority list for anonymous users authorities代表匿名用户的权限集合
	 */
	public AnonymousAuthenticationFilter(String key, Object principal, List<GrantedAuthority> authorities) {
		Assert.hasLength(key, "key cannot be null or empty");
		Assert.notNull(principal, "Anonymous authentication principal must be set");
		Assert.notNull(authorities, "Anonymous authorities must be set");
		this.key = key;
		this.principal = principal;
		this.authorities = authorities;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.hasLength(this.key, "key must have length");
		Assert.notNull(this.principal, "Anonymous authentication principal must be set");
		Assert.notNull(this.authorities, "Anonymous authorities must be set");
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		// 过滤器链都执行到匿名认证过滤器这儿了还没有身份信息，塞一个匿名身份进去
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			SecurityContextHolder.getContext().setAuthentication(createAuthentication((HttpServletRequest) req));
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.of(() -> "Set SecurityContextHolder to "
						+ SecurityContextHolder.getContext().getAuthentication()));
			}
			else {
				this.logger.debug("Set SecurityContextHolder to anonymous SecurityContext");
			}
		}
		else {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.of(() -> "Did not set SecurityContextHolder since already authenticated "
						+ SecurityContextHolder.getContext().getAuthentication()));
			}
		}
		chain.doFilter(req, res);
	}

	protected Authentication createAuthentication(HttpServletRequest request) {
		// 创建一个AnonymousAuthenticationToken
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(this.key, this.principal,
				this.authorities);
		token.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return token;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public Object getPrincipal() {
		return this.principal;
	}

	public List<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

}
