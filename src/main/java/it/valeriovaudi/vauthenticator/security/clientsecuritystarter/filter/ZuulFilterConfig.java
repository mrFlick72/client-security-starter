package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.filter;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.cloud.netflix.zuul.ZuulProxyAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnClass(ZuulProxyAutoConfiguration.class)
public class ZuulFilterConfig {

    @Bean
    public ZuulBearerOAuth2TokenRelayFilter bearerOAuth2TokenRelayFilter(OAuth2TokenResolver oAuth2TokenResolver) {
        return new ZuulBearerOAuth2TokenRelayFilter(oAuth2TokenResolver);
    }
}
