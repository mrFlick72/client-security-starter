package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

import java.io.IOException;

@Slf4j
public class BearerTokenInterceptor implements ClientHttpRequestInterceptor {
    private final OAuth2TokenResolver oAuth2TokenResolver;

    public BearerTokenInterceptor(OAuth2TokenResolver oAuth2TokenResolver) {
        this.oAuth2TokenResolver = oAuth2TokenResolver;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest httpRequest, byte[] bytes, ClientHttpRequestExecution execution) throws IOException {
        OAuth2AuthenticationToken currentUser =
                OAuth2AuthenticationToken.class.cast(SecurityContextHolder.getContext().getAuthentication());


        httpRequest.getHeaders()
                .add(HttpHeaders.AUTHORIZATION, "Bearer " + oAuth2TokenResolver.tokenFor(currentUser));

        return execution.execute(httpRequest, bytes);
    }

}
