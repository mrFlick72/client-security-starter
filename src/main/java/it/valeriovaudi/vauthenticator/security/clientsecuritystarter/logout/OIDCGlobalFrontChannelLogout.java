package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.logout;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class OIDCGlobalFrontChannelLogout {

    private final GlobalFrontChannelLogoutProvider globalFrontChannelLogoutProvider;

    public OIDCGlobalFrontChannelLogout(GlobalFrontChannelLogoutProvider globalFrontChannelLogoutProvider) {
        this.globalFrontChannelLogoutProvider = globalFrontChannelLogoutProvider;
    }

    @GetMapping(value = "/oidc_logout.html")
    public String logout(Model model, OAuth2AuthenticationToken authentication) {
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        String logoutUrl = globalFrontChannelLogoutProvider.getLogoutUrl(oidcUser.getIdToken());
        model.addAttribute("logoutUrl", logoutUrl);
        return "redirect:" + logoutUrl;
    }
}