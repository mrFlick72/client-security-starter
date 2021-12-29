package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.session.management;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpSession;
import java.time.Duration;

@Controller
public class SessionManagementIFrameController {

    private final String targetOrigin;
    private final String logoutUri;
    private final Duration pollingRate;

    public SessionManagementIFrameController(
            @Value("${vauthenticator.session-management.rp-iframe.origin}") String targetOrigin,
            @Value("${vauthenticator.session-management.rp-iframe.logout-uri}") String logoutUri,
            @Value("${vauthenticator.session-management.rp-iframe.polling-rate}") Duration pollingRate
    ) {
        this.targetOrigin = targetOrigin;
        this.logoutUri = logoutUri;
        this.pollingRate = pollingRate;
    }

    @GetMapping("/session/management")
    public String sessionManagerIframe(OAuth2AuthenticationToken principal, Model model, HttpSession session) {
        model.addAttribute("logout_uri", logoutUri);
        model.addAttribute("target_origin", targetOrigin);
        model.addAttribute("polling_rate", pollingRate.toMillis());
        model.addAttribute("client_id", principal.getPrincipal().getAttributes().get("azp"));
        model.addAttribute("session_state", session.getAttribute("op.session_state"));
        System.out.println(session.getAttribute("op.session_state"));
        return "session/management";
    }
}
