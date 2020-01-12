package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.filter;

import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;

import java.time.Duration;

@Configuration
@AutoConfigureAfter(OAuth2ClientAutoConfiguration.class)
public class OAuth2ResolverConfig {

    @Bean
    @ConditionalOnBean(OAuth2AuthorizedClientService.class)
    public OAuth2TokenResolver oAuth2TokenResolver(OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
        return new OAuth2RefreshableTokenResolver(Duration.ofSeconds(5), oAuth2AuthorizedClientService);
    }

}