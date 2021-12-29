package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

import java.security.Principal;

@Slf4j
public class VAuthenticatorUserNameResolver {

    private final String userNameSource;

    public VAuthenticatorUserNameResolver(String userNameSource) {
        this.userNameSource = userNameSource;
    }

    public String getUserNameFor(Authentication authentication) {
        return authentication.getName();
    }

    public String getUserNameFor(Principal principal) {
        return principal.getName();
    }

    public Mono<String> getUserNameFor(Object principal) {
        return Mono.defer(() -> {
            Authentication token = (Authentication) principal;
            return Mono.just(token.getName());
        });
    }
}
