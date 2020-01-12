package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import reactor.core.publisher.Mono;

public class VAuthenticatorUserNameResolver {

    public String getUserNameFor(Authentication authentication){
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        return  (String) oidcUser.getClaims().getOrDefault("email", "");
    }

    public Mono<String> getUserNameFor(Object principal) {
        return Mono.defer(() -> {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) principal;
            OidcUser oidcUser = (OidcUser) token.getPrincipal();
            System.out.println(oidcUser);
            return Mono.just((String) oidcUser.getClaims().getOrDefault("email", ""));
        });
    }
}
