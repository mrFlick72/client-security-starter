package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class VAuthenticatorUserConfig {

    @Bean
    public VAuthenticatorUserNameResolver vAuthenticatorUserNameResolver() {
        return new VAuthenticatorUserNameResolver("username");
    }
}
