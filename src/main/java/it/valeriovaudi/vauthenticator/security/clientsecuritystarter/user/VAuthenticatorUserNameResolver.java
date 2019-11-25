package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public class VAuthenticatorUserNameResolver {

    public String getUserNameFor(Authentication authentication){
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        return  (String) oidcUser.getClaims().getOrDefault("email", "");
    }
}
