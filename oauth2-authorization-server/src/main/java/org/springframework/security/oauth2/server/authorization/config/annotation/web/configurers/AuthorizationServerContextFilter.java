/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.io.IOException;

import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextResolver;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * A {@code Filter} that associates the {@link AuthorizationServerContext} to the {@link AuthorizationServerContextHolder}.
 *
 * @author Joe Grandja
 * @since 0.2.2
 * @see AuthorizationServerContext
 * @see AuthorizationServerContextHolder
 * @see AuthorizationServerSettings
 */
final class AuthorizationServerContextFilter extends OncePerRequestFilter {
	private final AuthorizationServerContextResolver authorizationServerContextResolver;

	AuthorizationServerContextFilter(AuthorizationServerContextResolver authorizationServerContextResolver) {
		Assert.notNull(authorizationServerContextResolver, "authorizationServerContextResolver cannot be null");
		this.authorizationServerContextResolver = authorizationServerContextResolver;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		try {
			AuthorizationServerContext authorizationServerContext = authorizationServerContextResolver.resolve(request);
			AuthorizationServerContextHolder.setContext(authorizationServerContext);
			filterChain.doFilter(request, response);
		} finally {
			AuthorizationServerContextHolder.resetContext();
		}
	}

}
