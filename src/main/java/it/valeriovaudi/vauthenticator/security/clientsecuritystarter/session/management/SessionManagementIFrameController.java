package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.session.management;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.Duration;

@Controller
public class SessionManagementIFrameController {

    private final boolean consoleDebug;
    private final String targetOrigin;
    private final String logoutUri;
    private final Duration pollingRate;

    public SessionManagementIFrameController(
            @Value("${consoleDebug:false}") boolean consoleDebug,
            @Value("${vauthenticator.session-management.rp-iframe.origin}") String targetOrigin,
            @Value("${vauthenticator.session-management.rp-iframe.logout-uri}") String logoutUri,
            @Value("${vauthenticator.session-management.rp-iframe.polling-rate}") Duration pollingRate
    ) {
        this.consoleDebug = consoleDebug;
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

        model.addAttribute("console_debug", consoleDebug);
        return "session/management";
    }
}
