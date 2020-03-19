package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.toList;

public class VAuthenticatorOAuth2User implements OAuth2User {

    public String username;
    public List<String> authorities;

    public String sub;
    public String name;
    public String family_name;
    public String given_name;
    public String middle_name;
    public String nickname;
    public String preferred_username;
    public String profile;
    public String picture;
    public String website;
    public String gender;
    public String birthdate;
    public String zoneinfo;
    public String locale;
    public String updated_at;
    public String email;
    public String email_verified;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities.stream().map(SimpleGrantedAuthority::new).collect(toList());
    }

    @Override
    public Map<String, Object> getAttributes() {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("username", username);
        attributes.put("authorities", authorities);
        attributes.put("sub", sub);
        attributes.put("name", name);
        attributes.put("family_name", family_name);
        attributes.put("given_name", given_name);
        attributes.put("middle_name", middle_name);
        attributes.put("nickname", nickname);
        attributes.put("preferred_username", preferred_username);
        attributes.put("profile", profile);
        attributes.put("picture", picture);
        attributes.put("website", website);
        attributes.put("gender", gender);
        attributes.put("birthdate", birthdate);
        attributes.put("zoneinfo", zoneinfo);
        attributes.put("locale", locale);
        attributes.put("updated_at", updated_at);
        attributes.put("email", email);
        attributes.put("email_verified", email_verified);

        return attributes;
    }

    @Override
    public String getName() {
        return username;
    }
}
