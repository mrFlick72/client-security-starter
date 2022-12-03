package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.RequestEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;

import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

@Slf4j
public class OAuth2RefreshableTokenResolver implements OAuth2TokenResolver {

    private final Duration amountToSubtract;
    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;


    public OAuth2RefreshableTokenResolver(Duration amountToSubtract,
                                          OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
        this.amountToSubtract = amountToSubtract;
        this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
    }

    @Override
    public String tokenFor(OAuth2AuthenticationToken currentUser) {
        OAuth2AuthorizedClient client =
                oAuth2AuthorizedClientService.
                        loadAuthorizedClient(currentUser.getAuthorizedClientRegistrationId(),
                                currentUser.getName());

        log.debug("getAuthorizedClientRegistrationId : " + currentUser.getAuthorizedClientRegistrationId());
        log.debug("currentUser : " + currentUser);
        log.debug("client : " + client);

        if (client == null) {
            return "";
        }
        if (isExpired(client.getAccessToken())) {
            log.debug("token have to refresh");
            refreshToken(client, currentUser);
        }
        return oAuth2AuthorizedClientService.
                loadAuthorizedClient(currentUser.getAuthorizedClientRegistrationId(),
                        currentUser.getName())
                .getAccessToken().getTokenValue();
    }


    private void refreshToken(OAuth2AuthorizedClient client, OAuth2AuthenticationToken currentUser) {
        OAuth2AccessTokenResponse oAuth2AccessTokenResponse = refreshTokenClient(client);
        if (oAuth2AccessTokenResponse == null || oAuth2AccessTokenResponse.getAccessToken() == null) {
            log.debug("refresh goes in error: oAuth2AccessTokenResponse is null");
            return;
        }

        log.debug("oAuth2AccessTokenResponse.getRefreshToken(): " + oAuth2AccessTokenResponse.getRefreshToken());
        log.debug("oAuth2AccessTokenResponse.getAccessToken(): " + oAuth2AccessTokenResponse.getAccessToken());

        OAuth2RefreshToken refreshToken = oAuth2AccessTokenResponse.getRefreshToken() != null
                ? oAuth2AccessTokenResponse.getRefreshToken()
                : client.getRefreshToken();

        OAuth2AuthorizedClient updatedClient = new OAuth2AuthorizedClient(
                client.getClientRegistration(),
                client.getPrincipalName(),
                oAuth2AccessTokenResponse.getAccessToken(),
                refreshToken
        );

        oAuth2AuthorizedClientService.saveAuthorizedClient(updatedClient, currentUser);
    }

    private OAuth2AccessTokenResponse refreshTokenClient(OAuth2AuthorizedClient currentClient) {
        LinkedMultiValueMap formParameters = new LinkedMultiValueMap<String, String>();
        formParameters.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
        formParameters.add(OAuth2ParameterNames.REFRESH_TOKEN, currentClient.getRefreshToken().getTokenValue());
        formParameters.add(OAuth2ParameterNames.REDIRECT_URI, currentClient.getClientRegistration().getRedirectUri());


        RequestEntity requestEntity = RequestEntity
                .post(URI.create(currentClient.getClientRegistration().getProviderDetails().getTokenUri()))
                .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                .body(formParameters);

        try {
            RestTemplate restTemplate = restTemplate(currentClient.getClientRegistration().getClientId(),
                    currentClient.getClientRegistration().getClientSecret());

            return restTemplate.exchange(requestEntity, OAuth2AccessTokenResponse.class)
                    .getBody();
        } catch (OAuth2AuthorizationException e) {
            log.error(String.format("Unable to refresh token %s", e.getMessage()), e);

            throw new OAuth2AuthenticationException(e.getError(), e);
        }
    }

    private RestTemplate restTemplate(String clientId, String clientSecret) {
        return new RestTemplateBuilder()
                .additionalMessageConverters(
                        new FormHttpMessageConverter(),
                        new OAuth2AccessTokenResponseHttpMessageConverter())
                .errorHandler(new OAuth2ErrorResponseErrorHandler())
                .basicAuthentication(clientId, clientSecret)
                .build();
    }

    private boolean isExpired(OAuth2AccessToken accessToken) {
        Instant now = Instant.now();
        Instant expiresAt = accessToken.getExpiresAt();

        log.debug("now: " + now);
        log.debug("expiresAt: " + expiresAt);
        log.debug("now.isAfter(expiresAt) " + now.isAfter(expiresAt.minus(amountToSubtract)));
        return now.isAfter(expiresAt.minus(amountToSubtract));
    }
}