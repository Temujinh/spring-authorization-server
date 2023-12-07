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

import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * A context that holds information of the Authorization Server runtime environment.
 *
 * @author Joe Grandja
 * @since 0.2.2
 * @see AuthorizationServerSettings
 * @see AuthorizationServerContextHolder
 */
public interface AuthorizationServerContext {

	/**
	 * Returns the {@code URL} of the Authorization Server's issuer identifier.
	 *
	 * @return the {@code URL} of the Authorization Server's issuer identifier
	 */
	String getIssuer();

	/**
	 * Returns the OAuth 2.0 Authorization endpoint.
	 *
	 * @return the Authorization endpoint
	 */
	String getAuthorizationEndpoint();

	/**
	 * Returns the OAuth 2.0 Device Authorization endpoint.
	 *
	 * @return the Device Authorization endpoint
	 * @since 1.1
	 */
	String getDeviceAuthorizationEndpoint();

	/**
	 * Returns the OAuth 2.0 Device Verification endpoint.
	 *
	 * @return the Device Verification endpoint
	 * @since 1.1
	 */
	String getDeviceVerificationEndpoint();

	/**
	 * Returns the OAuth 2.0 Token endpoint.
	 *
	 * @return the Token endpoint
	 */
	String getTokenEndpoint();

	/**
	 * Returns the JWK Set endpoint.
	 *
	 * @return the JWK Set endpoint
	 */
	String getJwkSetEndpoint();

	/**
	 * Returns the OAuth 2.0 Token Revocation endpoint.
	 *
	 * @return the Token Revocation endpoint
	 */
	String getTokenRevocationEndpoint();

	/**
	 * Returns the OAuth 2.0 Token Introspection endpoint.
	 *
	 * @return the Token Introspection endpoint
	 */
	String getTokenIntrospectionEndpoint();

	/**
	 * Returns the OpenID Connect 1.0 Client Registration endpoint.
	 *
	 * @return the OpenID Connect 1.0 Client Registration endpoint
	 */
	String getOidcClientRegistrationEndpoint();

	/**
	 * Returns the OpenID Connect 1.0 UserInfo endpoint.
	 *
	 * @return the OpenID Connect 1.0 UserInfo endpoint
	 */
	String getOidcUserInfoEndpoint();

	/**
	 * Returns the OpenID Connect 1.0 Logout endpoint.
	 *
	 * @return the OpenID Connect 1.0 Logout endpoint
	 */
	String getOidcLogoutEndpoint();

}
