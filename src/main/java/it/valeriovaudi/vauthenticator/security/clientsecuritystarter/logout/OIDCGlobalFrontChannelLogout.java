package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.logout;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Optional;

@Controller
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class OIDCGlobalFrontChannelLogout {

    private final GlobalFrontChannelLogoutProvider globalFrontChannelLogoutProvider;

    public OIDCGlobalFrontChannelLogout(GlobalFrontChannelLogoutProvider globalFrontChannelLogoutProvider) {
        this.globalFrontChannelLogoutProvider = globalFrontChannelLogoutProvider;
    }

    @GetMapping(value = "/oidc_logout.html")
    public String logout(Model model, OAuth2AuthenticationToken authentication) {
        OidcUser oidcUser = (OidcUser) Optional.ofNullable(authentication)
                .map(OAuth2AuthenticationToken::getPrincipal)
                .orElse(null);

        OidcIdToken idToken = Optional.ofNullable(oidcUser).map(user -> user.getIdToken()).orElse(null);
        String logoutUrl = globalFrontChannelLogoutProvider.getLogoutUrl(idToken);
        model.addAttribute("logoutUrl", logoutUrl);
        return "redirect:" + logoutUrl;
    }
}