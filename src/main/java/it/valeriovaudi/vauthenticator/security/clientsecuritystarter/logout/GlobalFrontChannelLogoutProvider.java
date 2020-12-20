package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.logout;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.web.client.RestOperations;

import java.util.HashMap;
import java.util.Optional;

public class GlobalFrontChannelLogoutProvider {

    private final String postLogoutRedirectUri;
    private final String oidConnectDiscoveryEndPoint;
    private final String oidConnectEndSessionEndpoint;
    private final RestOperations restTemplate;

    public GlobalFrontChannelLogoutProvider(String postLogoutRedirectUri,
                                            String oidConnectDiscoveryEndPoint,
                                            String oidConnectEndSessionEndpoint,
                                            RestOperations restTemplate) {
        this.postLogoutRedirectUri = postLogoutRedirectUri;
        this.oidConnectDiscoveryEndPoint = oidConnectDiscoveryEndPoint;
        this.oidConnectEndSessionEndpoint = oidConnectEndSessionEndpoint;
        this.restTemplate = restTemplate;
    }

    public String getLogoutUrl(OidcIdToken oidcIdToken) {
        String logoutUrl = baseLogoutUrlFromOP();
        return logoutUrl +
                "?post_logout_redirect_uri=" + postLogoutRedirectUri +
                "&id_token_hint=" + oidcIdToken.getTokenValue();
    }

    private String baseLogoutUrlFromOP() {
        return Optional.ofNullable(oidConnectDiscoveryEndPoint)
                .map(oidConnectDiscoveryEndPoint -> {
                    HashMap<String, String> forObject = restTemplate.getForObject(oidConnectDiscoveryEndPoint, HashMap.class);
                    return forObject.get("end_session_endpoint");
                }).orElse(oidConnectEndSessionEndpoint);
    }
}
