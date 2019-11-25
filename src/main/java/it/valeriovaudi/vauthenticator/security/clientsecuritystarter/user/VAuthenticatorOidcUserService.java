package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

public class VAuthenticatorOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final Map<String, Class<? extends OAuth2User>> customUserTypesMapping;
    private final OidcUserService delegate;

    public VAuthenticatorOidcUserService(Map<String, Class<? extends OAuth2User>> customUserTypesMapping, OidcUserService delegate) {
        this.customUserTypesMapping = customUserTypesMapping;
        this.delegate = delegate;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        CustomUserTypesOAuth2UserService customUserTypesOAuth2UserService = new CustomUserTypesOAuth2UserService(customUserTypesMapping);
        delegate.setOauth2UserService(customUserTypesOAuth2UserService);

        // Delegate to the default implementation for loading a user
        final OidcUser oidcUser = delegate.loadUser(userRequest);

        OAuth2User oAuth2User = customUserTypesOAuth2UserService.loadUser(userRequest);
        Collection<? extends GrantedAuthority> mappedAuthorities = oAuth2User.getAuthorities()
                .stream()
                .map(authority ->
                        new OidcUserAuthority(authority.getAuthority(),
                                oidcUser.getIdToken(),
                                oidcUser.getUserInfo()))
                .collect(Collectors.toList());

        return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }
}