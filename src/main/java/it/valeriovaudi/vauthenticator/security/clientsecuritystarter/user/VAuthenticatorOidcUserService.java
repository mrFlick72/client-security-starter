package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.util.*;
import java.util.stream.Collectors;

public class VAuthenticatorOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcUserService delegate;
    private final String authoritiesClaimName;

    public VAuthenticatorOidcUserService(OidcUserService delegate, String authoritiesClaimName) {
        this.delegate = delegate;
        this.authoritiesClaimName = authoritiesClaimName;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = delegate.loadUser(userRequest);
        Collection<GrantedAuthority> mappedAuthorities = authoritiesFor(oidcUser);

        return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }

    private Set<GrantedAuthority> authoritiesFor(OidcUser user) {
        List<String> authorities = authoritiesFrom(user);
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .map(authority -> new OidcUserAuthority(authority.getAuthority(), user.getIdToken(), user.getUserInfo()))
                .collect(Collectors.toSet());
    }

    private List<String> authoritiesFrom(OidcUser oidcUser) {
        List<String> authoritiesClaim = oidcUser.getClaim(authoritiesClaimName);
        return Optional.ofNullable(authoritiesClaim).orElse(Collections.emptyList());
    }
}