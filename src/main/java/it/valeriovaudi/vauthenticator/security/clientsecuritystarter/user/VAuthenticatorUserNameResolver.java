package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import reactor.core.publisher.Mono;

import java.security.Principal;

@Slf4j
public class VAuthenticatorUserNameResolver {

    private final String userNameSource;

    public VAuthenticatorUserNameResolver(String userNameSource) {
        this.userNameSource = userNameSource;
    }

    public String getUserNameFor(Authentication authentication){
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        log.debug("oidcUser: " + oidcUser);
        return  (String) oidcUser.getClaims().getOrDefault(userNameSource, "");
    }

    public String getUserNameFor(Principal principal){
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) principal;
        OidcUser oidcUser = (OidcUser) token.getPrincipal();
        log.debug("oidcUser: " + oidcUser);
        return  (String) oidcUser.getClaims().getOrDefault(userNameSource, "");
    }

    public Mono<String> getUserNameFor(Object principal) {
        return Mono.defer(() -> {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) principal;
            OidcUser oidcUser = (OidcUser) token.getPrincipal();
            log.debug("oidcUser: " + oidcUser);
            return Mono.just((String) oidcUser.getClaims().getOrDefault(userNameSource, ""));
        });
    }
}
