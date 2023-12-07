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
package org.springframework.security.oauth2.server.authorization.context;

import java.util.function.Supplier;

import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;

public class DefaultAuthorizationServerContextResolver implements AuthorizationServerContextResolver {
	private final AuthorizationServerSettings authorizationServerSettings;

	public DefaultAuthorizationServerContextResolver(AuthorizationServerSettings authorizationServerSettings) {
		this.authorizationServerSettings = authorizationServerSettings;
	}

	@Override
	public AuthorizationServerContext resolve(HttpServletRequest request) {
		AuthorizationServerContext authorizationServerContext =
				new DefaultAuthorizationServerContext(
						() -> resolveIssuer(this.authorizationServerSettings, request),
						this.authorizationServerSettings);
		return authorizationServerContext;
	}

	private static String resolveIssuer(AuthorizationServerSettings authorizationServerSettings, HttpServletRequest request) {
		return authorizationServerSettings.getIssuer() != null ?
				authorizationServerSettings.getIssuer() :
				getContextPath(request);
	}

	private static String getContextPath(HttpServletRequest request) {
		// @formatter:off
		return UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replacePath(request.getContextPath())
				.replaceQuery(null)
				.fragment(null)
				.build()
				.toUriString();
		// @formatter:on
	}

	private static final class DefaultAuthorizationServerContext implements AuthorizationServerContext {
		private final Supplier<String> issuerSupplier;
		private final AuthorizationServerSettings authorizationServerSettings;

		private DefaultAuthorizationServerContext(Supplier<String> issuerSupplier, AuthorizationServerSettings authorizationServerSettings) {
			this.issuerSupplier = issuerSupplier;
			this.authorizationServerSettings = authorizationServerSettings;
		}

		@Override
		public String getIssuer() {
			return this.issuerSupplier.get();
		}

		@Override
		public String getAuthorizationEndpoint() {
			return authorizationServerSettings.getAuthorizationEndpoint();
		}

		@Override
		public String getDeviceAuthorizationEndpoint() {
			return authorizationServerSettings.getDeviceAuthorizationEndpoint();
		}

		@Override
		public String getDeviceVerificationEndpoint() {
			return authorizationServerSettings.getDeviceVerificationEndpoint();
		}

		@Override
		public String getTokenEndpoint() {
			return authorizationServerSettings.getTokenEndpoint();
		}

		@Override
		public String getJwkSetEndpoint() {
			return authorizationServerSettings.getJwkSetEndpoint();
		}

		@Override
		public String getTokenRevocationEndpoint() {
			return authorizationServerSettings.getTokenRevocationEndpoint();
		}

		@Override
		public String getTokenIntrospectionEndpoint() {
			return authorizationServerSettings.getTokenIntrospectionEndpoint();
		}

		@Override
		public String getOidcClientRegistrationEndpoint() {
			return authorizationServerSettings.getOidcClientRegistrationEndpoint();
		}

		@Override
		public String getOidcUserInfoEndpoint() {
			return authorizationServerSettings.getOidcUserInfoEndpoint();
		}

		@Override
		public String getOidcLogoutEndpoint() {
			return authorizationServerSettings.getOidcLogoutEndpoint();
		}

	}

}
