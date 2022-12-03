package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.session.management;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;

@AutoConfiguration
@ConditionalOnProperty(value = "vauthenticator.session-management.enabled", havingValue = "true")
@ComponentScan("it.valeriovaudi.vauthenticator.security.clientsecuritystarter.session.management")
public class OIDCSessionManagementConfig {

    @Bean
    public OAuth2AuthorizationRequestResolverWithSessionState oAuth2AuthorizationRequestResolverWithSessionState(
            ClientRegistrationRepository clientRegistrationRepository
    ) {
        return new OAuth2AuthorizationRequestResolverWithSessionState(
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
                )
        );
    }
}
