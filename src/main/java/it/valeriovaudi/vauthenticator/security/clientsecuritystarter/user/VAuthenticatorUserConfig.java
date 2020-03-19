package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class VAuthenticatorUserConfig {

    @Bean
    public VAuthenticatorUserNameResolver vAuthenticatorUserNameResolver(@Value("${spring.security.oauth2.client.provider.vauthenticator.user-name-attribute:username}") String userNameSource) {
        return new VAuthenticatorUserNameResolver(userNameSource);
    }
}
