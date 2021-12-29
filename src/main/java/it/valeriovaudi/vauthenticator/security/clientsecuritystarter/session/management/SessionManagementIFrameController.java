package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.session.management;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpSession;

@Controller
public class SessionManagementIFrameController {

    private final String targetOrigin;
    private final String logoutUri;

    public SessionManagementIFrameController(
            @Value("${vauthenticator.session-management.rp-iframe.origin}") String targetOrigin,
            @Value("${vauthenticator.session-management.rp-iframe.logout-uri}") String logoutUri
    ) {
        this.targetOrigin = targetOrigin;
        this.logoutUri = logoutUri;
    }

    @GetMapping("/session/management")
    public String sessionManagerIframe(OAuth2AuthenticationToken principal, Model model, HttpSession session) {
        model.addAttribute("logout_uri", logoutUri);
        model.addAttribute("target_origin", targetOrigin);
        model.addAttribute("client_id", principal.getAuthorizedClientRegistrationId());
        model.addAttribute("session_state", session.getAttribute("op.session_state"));
        return "session/management";
    }
}
