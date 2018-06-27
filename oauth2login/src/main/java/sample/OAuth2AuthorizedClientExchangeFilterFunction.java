package sample;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import net.minidev.json.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.util.CollectionUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFilterFunctions;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import static org.springframework.security.web.http.SecurityHeaders.bearerToken;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.Credentials.basicAuthenticationCredentials;

/**
 * @author Rob Winch
 * @since 5.1
 */
public final class OAuth2AuthorizedClientExchangeFilterFunction implements
		ExchangeFilterFunction {

	private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

	/**
	 * The request attribute name used to locate the {@link OAuth2AuthorizedClient}.
	 */
	private static final String OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME = OAuth2AuthorizedClient.class.getName();

	private Clock clock = Clock.systemUTC();

	private Duration expiresOffset = Duration.ofMinutes(1);

	private ReactiveOAuth2AuthorizedClientService authorizedClientService;

	public OAuth2AuthorizedClientExchangeFilterFunction() {}

	public OAuth2AuthorizedClientExchangeFilterFunction(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		this.authorizedClientService = authorizedClientService;
	}

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link OAuth2AuthorizedClient} to be used for
	 * providing the Bearer Token. Example usage:
	 *
	 * <pre>
	 * Mono<String> response = this.webClient
	 *    .get()
	 *    .uri(uri)
	 *    .attributes(oauth2AuthorizedClient(authorizedClient))
	 *    // ...
	 *    .retrieve()
	 *    .bodyToMono(String.class);
	 * </pre>
	 *
	 * @param authorizedClient the {@link OAuth2AuthorizedClient} to use.
	 * @return the {@link Consumer} to populate the
	 */
	public static Consumer<Map<String, Object>> oauth2AuthorizedClient(OAuth2AuthorizedClient authorizedClient) {
		return attributes -> attributes.put(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME, authorizedClient);
	}

	@Override
	public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
		Optional<OAuth2AuthorizedClient> attribute = request.attribute(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME)
				.map(OAuth2AuthorizedClient.class::cast);
		return Mono.justOrEmpty(attribute)
				.flatMap(authorizedClient -> authorizedClient(next, authorizedClient))
				.map(authorizedClient -> bearer(request, authorizedClient))
				.flatMap(next::exchange)
				.switchIfEmpty(next.exchange(request));
	}

	private Mono<OAuth2AuthorizedClient> authorizedClient(ExchangeFunction next, OAuth2AuthorizedClient authorizedClient) {
		if (shouldRefresh(authorizedClient)) {
			ClientRegistration clientRegistration = authorizedClient
					.getClientRegistration();
			String tokenUri = clientRegistration
					.getProviderDetails().getTokenUri();
			ClientRequest request = ClientRequest.create(HttpMethod.POST, URI.create(tokenUri))
					.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.headers(httpBasic(clientRegistration.getClientId(), clientRegistration.getClientSecret()))
					.body(refreshTokenBody(authorizedClient.getRefreshToken().getTokenValue()))
					.build();
			return next.exchange(request)
				.flatMap(response -> response.bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {}))
				.map(json -> parse(json))
				.flatMap(tokenResponse -> accessTokenResponse(tokenResponse))
				.map(accessTokenResponse -> {
					AccessToken accessToken = accessTokenResponse.getTokens().getAccessToken();
					OAuth2AccessToken.TokenType accessTokenType = null;
					if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(
							accessToken.getType().getValue())) {
						accessTokenType = OAuth2AccessToken.TokenType.BEARER;
					}
					long expiresIn = accessToken.getLifetime();

					Set<String> scopes = new LinkedHashSet<>(accessToken.getScope().toStringList());

					String refreshToken = null;
					if (accessTokenResponse.getTokens().getRefreshToken() != null) {
						refreshToken = accessTokenResponse.getTokens().getRefreshToken().getValue();
					}

					Map<String, Object> additionalParameters = new LinkedHashMap<>(
							accessTokenResponse.getCustomParameters());

					return OAuth2AccessTokenResponse.withToken(accessToken.getValue())
							.tokenType(accessTokenType)
							.expiresIn(expiresIn)
							.scopes(scopes)
							.refreshToken(refreshToken)
							.additionalParameters(additionalParameters)
							.build();
				})
				.map(accessTokenResponse -> new OAuth2AuthorizedClient(authorizedClient.getClientRegistration(), authorizedClient.getPrincipalName(), accessTokenResponse.getAccessToken(), accessTokenResponse.getRefreshToken()))
				.flatMap(result -> ReactiveSecurityContextHolder.getContext()
						.map(SecurityContext::getAuthentication)
						.flatMap(principal -> this.authorizedClientService.saveAuthorizedClient(result, principal))
						.thenReturn(result));
		}
		return Mono.just(authorizedClient);
	}

	private static Consumer<HttpHeaders> httpBasic(String username, String password) {
		return httpHeaders -> {
			String credentialsString = username + ":" + password;
			byte[] credentialBytes = credentialsString.getBytes(StandardCharsets.ISO_8859_1);
			byte[] encodedBytes = Base64.getEncoder().encode(credentialBytes);
			String encodedCredentials = new String(encodedBytes, StandardCharsets.ISO_8859_1);
			httpHeaders.set(HttpHeaders.AUTHORIZATION, "Basic " + encodedCredentials);
		};
	}

	private static TokenResponse parse(Map<String, String> json) {
		try {
			return TokenResponse.parse(new JSONObject(json));
		}
		catch (ParseException pe) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
					"An error occurred parsing the Access Token response: " + pe.getMessage(), null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), pe);
		}
	}

	private static Mono<AccessTokenResponse> accessTokenResponse(TokenResponse tokenResponse) {
		if (tokenResponse.indicatesSuccess()) {
			return Mono.just(tokenResponse)
					.cast(AccessTokenResponse.class);
		}
		TokenErrorResponse tokenErrorResponse = (TokenErrorResponse) tokenResponse;
		ErrorObject errorObject = tokenErrorResponse.getErrorObject();
		OAuth2Error oauth2Error = new OAuth2Error(errorObject.getCode(),
				errorObject.getDescription(), (errorObject.getURI() != null ?
				errorObject.getURI().toString() :
				null));

		return Mono.error(new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString()));
	}

	private boolean shouldRefresh(OAuth2AuthorizedClient authorizedClient) {
		if (this.authorizedClientService == null) {
			return false;
		}
		OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
		if (refreshToken == null) {
			return false;
		}
		Instant now = this.clock.instant();
		Instant expiresAt = authorizedClient.getAccessToken().getExpiresAt();
		if (now.isAfter(expiresAt.minus(this.expiresOffset))) {
			return true;
		}
		return false;
	}

	private ClientRequest bearer(ClientRequest request, OAuth2AuthorizedClient authorizedClient) {
		return ClientRequest.from(request)
				.headers(bearerToken(authorizedClient.getAccessToken().getTokenValue()))
				.build();
	}

	private static BodyInserters.FormInserter<String> refreshTokenBody(String refreshToken) {
		return BodyInserters
				.fromFormData("grant_type", AuthorizationGrantType.REFRESH_TOKEN.getValue())
				.with("refresh_token", refreshToken);
	}
}
