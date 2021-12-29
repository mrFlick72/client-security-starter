package it.valeriovaudi.vauthenticator.security.clientsecuritystarter.session.management;

import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import javax.servlet.http.HttpServletRequest;

public class OAuth2AuthorizationRequestResolverWithSessionState implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver delegate;

    public OAuth2AuthorizationRequestResolverWithSessionState(OAuth2AuthorizationRequestResolver delegate) {
        this.delegate = delegate;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        if (request.getParameter("session_state") != null) {
            request.getSession().setAttribute("op.session_state", request.getParameter("session_state"));
        }
        return delegate.resolve(request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        if (request.getParameter("session_state") != null) {
            request.getSession().setAttribute("op.session_state", request.getParameter("session_state"));
        }
        return delegate.resolve(request, clientRegistrationId);
    }
}