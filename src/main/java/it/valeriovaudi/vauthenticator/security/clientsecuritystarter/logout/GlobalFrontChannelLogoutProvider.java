package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.logout;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.web.client.RestOperations;

import java.util.HashMap;

public class GlobalFrontChannelLogoutProvider {

    private final String postLogoutRedirectUri;
    private final String oidConnectDiscoveryEndPoint;
    private final RestOperations restTemplate;

    public GlobalFrontChannelLogoutProvider(String postLogoutRedirectUri, String oidConnectDiscoveryEndPoint, RestOperations restTemplate) {
        this.postLogoutRedirectUri = postLogoutRedirectUri;
        this.oidConnectDiscoveryEndPoint = oidConnectDiscoveryEndPoint;
        this.restTemplate = restTemplate;
    }

    public String getLogoutUrl(OidcIdToken oidcIdToken) {
        String logoutUrl = baseLogoutUrlFromOP();
        return logoutUrl +
                "?post_logout_redirect_uri=" + postLogoutRedirectUri +
                "&id_token_hint=" + oidcIdToken.getTokenValue();
    }

    private String baseLogoutUrlFromOP() {
        HashMap<String, String> forObject = restTemplate.getForObject(oidConnectDiscoveryEndPoint, HashMap.class);
        return forObject.get("end_session_endpoint");
    }
}
