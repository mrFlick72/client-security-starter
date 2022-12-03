package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@AutoConfiguration
public class VAuthenticatorUserConfig {

    @Bean
    public VAuthenticatorUserNameResolver vAuthenticatorUserNameResolver() {
        return new VAuthenticatorUserNameResolver("username");
    }
}
