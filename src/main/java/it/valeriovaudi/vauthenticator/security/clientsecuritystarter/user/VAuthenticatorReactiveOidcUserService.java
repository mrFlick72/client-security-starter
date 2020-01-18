package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.stream.Collectors;

public class VAuthenticatorReactiveOidcUserService implements ReactiveOAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcReactiveOAuth2UserService delegate;
    private final CustomUserTypesOAuth2UserService customUserTypesOAuth2UserService;

    public VAuthenticatorReactiveOidcUserService(OidcReactiveOAuth2UserService delegate,
                                                 CustomUserTypesOAuth2UserService customUserTypesOAuth2UserService) {
        this.delegate = delegate;
        this.customUserTypesOAuth2UserService = customUserTypesOAuth2UserService;
    }

    public Mono<OidcUser> loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        Mono<OAuth2User> oAuth2User = Mono.fromCallable(() -> customUserTypesOAuth2UserService.loadUser(userRequest));
        Mono<OidcUser> delegate = this.delegate.loadUser(userRequest);
        return Mono.zip(delegate, oAuth2User, (oidcUser, oAuth2User1) -> {
            Collection<? extends GrantedAuthority> mappedAuthorities = oAuth2User1.getAuthorities().stream().map((authority) -> new OidcUserAuthority(authority.getAuthority(), oidcUser.getIdToken(), oidcUser.getUserInfo())).collect(Collectors.toList());
            DefaultOidcUser defaultOidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
            return defaultOidcUser;
        });
    }
}
