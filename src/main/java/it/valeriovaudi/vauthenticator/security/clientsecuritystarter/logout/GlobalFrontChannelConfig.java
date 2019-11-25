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

    @Bean
    @ConditionalOnProperty(value = {"postLogoutRedirectUri", "auth.oidcIss"})
    public GlobalFrontChannelLogoutProvider globalFrontChannelLogoutProvider(@Value("${postLogoutRedirectUri}") String postLogoutRedirectUri,
                                                                             @Value("${auth.oidcIss}") String oidConnectDiscoveryEndPoint) {
        return new GlobalFrontChannelLogoutProvider(postLogoutRedirectUri,
                oidConnectDiscoveryEndPoint + "/.well-known/openid-configuration",
                new RestTemplate());
    }

}
