package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.security;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientId;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.Assert;

public class RedisOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {
    private final RedisTemplate authorizedClients;
    private final ClientRegistrationRepository clientRegistrationRepository;

    public RedisOAuth2AuthorizedClientService(RedisTemplate authorizedClients, ClientRegistrationRepository clientRegistrationRepository) {
        this.authorizedClients = authorizedClients;
        this.clientRegistrationRepository = clientRegistrationRepository;
    }


    @Override
    @SuppressWarnings("unchecked")
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        ClientRegistration registration = this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
        if (registration == null) {
            return null;
        }
        OAuth2AuthorizedClientId oAuth2AuthorizedClientId = new OAuth2AuthorizedClientId(clientRegistrationId, principalName);
        return (T) this.authorizedClients.opsForHash().get(oAuth2AuthorizedClientId, oAuth2AuthorizedClientId.hashCode());
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        Assert.notNull(authorizedClient, "authorizedClient cannot be null");
        Assert.notNull(principal, "principal cannot be null");

        OAuth2AuthorizedClientId oAuth2AuthorizedClientId =
                new OAuth2AuthorizedClientId(authorizedClient.getClientRegistration().getRegistrationId(), principal.getName());
        this.authorizedClients.opsForHash().put(oAuth2AuthorizedClientId, oAuth2AuthorizedClientId.hashCode(), authorizedClient);
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        ClientRegistration registration = this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
        if (registration != null) {
            OAuth2AuthorizedClientId oAuth2AuthorizedClientId = new OAuth2AuthorizedClientId(clientRegistrationId, principalName);
            this.authorizedClients.opsForHash().delete(oAuth2AuthorizedClientId, oAuth2AuthorizedClientId.hashCode());
        }
    }
}
