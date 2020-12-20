package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.logout;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;

@Configuration
@ComponentScan("it.valeriovaudi.vauthenticator.security.clientsecuritystarter.logout")
public class GlobalFrontChannelConfig {

    @Bean("globalFrontChannelLogoutProvider")
    @ConditionalOnProperty(value = {"postLogoutRedirectUri", "auth.oidcIss","preferDiscovery"})
    public GlobalFrontChannelLogoutProvider globalFrontChannelLogoutProviderWithDiscovery(@Value("${postLogoutRedirectUri}") String postLogoutRedirectUri,
                                                                             @Value("${auth.oidcIss}") String oidConnectDiscoveryEndPoint) {
        return new GlobalFrontChannelLogoutProvider(postLogoutRedirectUri,
                oidConnectDiscoveryEndPoint + "/.well-known/openid-configuration",
                null,
                new RestTemplate());
    }

    @Bean("globalFrontChannelLogoutProvider")
    @ConditionalOnProperty(value = {"endSessionWithoutDiscovery"})
    public GlobalFrontChannelLogoutProvider globalFrontChannelLogoutProviderWithoutDiscovery(@Value("${postLogoutRedirectUri:''}") String postLogoutRedirectUri,
                                                                             @Value("${oidcEndSessionUrl}") String oidcEndSessionUrl) {
        return new GlobalFrontChannelLogoutProvider(postLogoutRedirectUri,
                null,
                oidcEndSessionUrl,
                null);
    }

}
