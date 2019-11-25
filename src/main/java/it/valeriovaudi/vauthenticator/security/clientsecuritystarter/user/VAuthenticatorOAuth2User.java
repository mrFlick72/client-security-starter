package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.toList;

public class VAuthenticatorOAuth2User implements OAuth2User {

    public String username;
    public List<String> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities.stream().map(SimpleGrantedAuthority::new).collect(toList());
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of("username", username, "authorities", authorities);
    }

    @Override
    public String getName() {
        return username;
    }
}
