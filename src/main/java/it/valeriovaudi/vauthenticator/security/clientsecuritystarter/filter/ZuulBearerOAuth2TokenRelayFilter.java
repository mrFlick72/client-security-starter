package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.filter;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

@Slf4j
public class ZuulBearerOAuth2TokenRelayFilter extends ZuulFilter {

    private final OAuth2TokenResolver oAuth2TokenResolver;

    public ZuulBearerOAuth2TokenRelayFilter(OAuth2TokenResolver oAuth2TokenResolver) {
        this.oAuth2TokenResolver = oAuth2TokenResolver;
    }

    public int filterOrder() {
        return 10;
    }

    public String filterType() {
        return "pre";
    }

    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        OAuth2AuthenticationToken currentUser =
                OAuth2AuthenticationToken.class.cast(SecurityContextHolder.getContext().getAuthentication());
        String authorization = oAuth2TokenResolver.tokenFor(currentUser);

        log.debug("currentUser " + currentUser);
        log.debug("authorization " + authorization);

        ctx.addZuulRequestHeader(HttpHeaders.AUTHORIZATION, "Bearer " + authorization);
        return null;
    }
}
