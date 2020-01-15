package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.logout;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.cloud.client.ConditionalOnReactiveDiscoveryEnabled;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.result.view.Rendering;

@Controller
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
public class OIDCReactiveGlobalFrontChannelLogout {

    private final GlobalFrontChannelLogoutProvider globalFrontChannelLogoutProvider;

    public OIDCReactiveGlobalFrontChannelLogout(GlobalFrontChannelLogoutProvider globalFrontChannelLogoutProvider) {
        this.globalFrontChannelLogoutProvider = globalFrontChannelLogoutProvider;
    }

    @GetMapping(value = "/oidc_logout.html")
    public Rendering logout(OAuth2AuthenticationToken authentication) {
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        String logoutUrl = globalFrontChannelLogoutProvider.getLogoutUrl(oidcUser.getIdToken());

        return Rendering.redirectTo(logoutUrl).modelAttribute("logoutUrl", logoutUrl).build() ;
    }
}