/*
 * Copyright 2020-2023 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.oidc.web;

import java.io.IOException;
import java.util.List;
import java.util.function.Consumer;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.http.converter.OidcProviderConfigurationHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * A {@code Filter} that processes OpenID Provider Configuration Requests.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 * @since 0.1.0
 * @see OidcProviderConfiguration
 * @see AuthorizationServerSettings
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">4.1. OpenID Provider Configuration Request</a>
 */
public final class OidcProviderConfigurationEndpointFilter extends OncePerRequestFilter {
	private final RequestMatcher requestMatcher;
	private final OidcProviderConfigurationHttpMessageConverter providerConfigurationHttpMessageConverter =
			new OidcProviderConfigurationHttpMessageConverter();
	private Consumer<OidcProviderConfiguration.Builder> providerConfigurationCustomizer = (providerConfiguration) -> {};

	public OidcProviderConfigurationEndpointFilter(String configurationEndpointUri) {
		this(createDefaultRequestMatcher(configurationEndpointUri));
	}

	public OidcProviderConfigurationEndpointFilter(RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
	}

	public static RequestMatcher createDefaultRequestMatcher(String configurationEndpointUri) {
		Assert.hasText(configurationEndpointUri, "configurationEndpointUri cannot be empty");
		return new AntPathRequestMatcher(configurationEndpointUri, HttpMethod.GET.name());
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@link OidcProviderConfiguration.Builder}
	 * allowing the ability to customize the claims of the OpenID Provider's configuration.
	 *
	 * @param providerConfigurationCustomizer the {@code Consumer} providing access to the {@link OidcProviderConfiguration.Builder}
	 * @since 0.4.0
	 */
	public void setProviderConfigurationCustomizer(Consumer<OidcProviderConfiguration.Builder> providerConfigurationCustomizer) {
		Assert.notNull(providerConfigurationCustomizer, "providerConfigurationCustomizer cannot be null");
		this.providerConfigurationCustomizer = providerConfigurationCustomizer;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
		String issuer = authorizationServerContext.getIssuer();

		OidcProviderConfiguration.Builder providerConfiguration = OidcProviderConfiguration.builder()
				.issuer(issuer)
				.authorizationEndpoint(asUrl(issuer, authorizationServerContext.getAuthorizationEndpoint()))
				.deviceAuthorizationEndpoint(asUrl(issuer, authorizationServerContext.getDeviceAuthorizationEndpoint()))
				.tokenEndpoint(asUrl(issuer, authorizationServerContext.getTokenEndpoint()))
				.tokenEndpointAuthenticationMethods(clientAuthenticationMethods())
				.jwkSetUrl(asUrl(issuer, authorizationServerContext.getJwkSetEndpoint()))
				.userInfoEndpoint(asUrl(issuer, authorizationServerContext.getOidcUserInfoEndpoint()))
				.endSessionEndpoint(asUrl(issuer, authorizationServerContext.getOidcLogoutEndpoint()))
				.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.grantType(AuthorizationGrantType.REFRESH_TOKEN.getValue())
				.grantType(AuthorizationGrantType.DEVICE_CODE.getValue())
				.tokenRevocationEndpoint(asUrl(issuer, authorizationServerContext.getTokenRevocationEndpoint()))
				.tokenRevocationEndpointAuthenticationMethods(clientAuthenticationMethods())
				.tokenIntrospectionEndpoint(asUrl(issuer, authorizationServerContext.getTokenIntrospectionEndpoint()))
				.tokenIntrospectionEndpointAuthenticationMethods(clientAuthenticationMethods())
				.subjectType("public")
				.idTokenSigningAlgorithm(SignatureAlgorithm.RS256.getName())
				.scope(OidcScopes.OPENID);

		this.providerConfigurationCustomizer.accept(providerConfiguration);

		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.providerConfigurationHttpMessageConverter.write(
				providerConfiguration.build(), MediaType.APPLICATION_JSON, httpResponse);
	}

	private static Consumer<List<String>> clientAuthenticationMethods() {
		return (authenticationMethods) -> {
			authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
			authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());
			authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue());
			authenticationMethods.add(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());
		};
	}

	private static String asUrl(String issuer, String endpoint) {
		return UriComponentsBuilder.fromUriString(issuer).path(endpoint).build().toUriString();
	}

}
