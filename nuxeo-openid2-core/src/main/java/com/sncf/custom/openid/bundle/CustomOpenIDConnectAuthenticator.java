package com.sncf.custom.openid.bundle;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentModelList;
import org.nuxeo.ecm.core.api.NuxeoException;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.oauth2.openid.OpenIDConnectProvider;
import org.nuxeo.ecm.platform.oauth2.openid.OpenIDConnectProviderRegistry;
import org.nuxeo.ecm.platform.oauth2.openid.RedirectUriResolver;
import org.nuxeo.ecm.platform.oauth2.openid.auth.OpenIDConnectAuthenticator;
import org.nuxeo.ecm.platform.oauth2.openid.auth.OpenIDUserInfo;
import org.nuxeo.ecm.platform.oauth2.openid.auth.UserResolver;
import org.nuxeo.ecm.platform.oauth2.providers.NuxeoOAuth2ServiceProvider;
import org.nuxeo.ecm.platform.oauth2.providers.OAuth2ServiceProvider;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.http.HttpMediaType;
import com.google.api.client.http.HttpResponse;


public class CustomOpenIDConnectAuthenticator extends OpenIDConnectAuthenticator {

    private static final Log log = LogFactory.getLog(CustomOpenIDConnectAuthenticator.class);
    
    OAuth2ServiceProvider oauth2Provider;

    protected RedirectUriResolver redirectUriResolver;
	
	@Override
    public UserIdentificationInfo retrieveIdentityFromOAuth(HttpServletRequest req, HttpServletResponse resp) {

        // Getting the "error" URL parameter
        String error = req.getParameter(ERROR_URL_PARAM_NAME);

        // / Checking if there was an error such as the user denied access
        if (error != null && error.length() > 0) {
            sendError(req, "There was an error: \"" + error + "\".");
            return null;
        }

        // Getting the "code" URL parameter
        String code = req.getParameter(CODE_URL_PARAM_NAME);

        // Checking conditions on the "code" URL parameter
        if (code == null || code.isEmpty()) {
            sendError(req, "There was an error: \"" + code + "\".");
            return null;
        }

        // Getting the "provider" URL parameter
        String serviceProviderName = req.getParameter(PROVIDER_URL_PARAM_NAME);

        // Checking conditions on the "provider" URL parameter
        if (serviceProviderName == null || serviceProviderName.isEmpty()) {
            sendError(req, "Missing OpenID Connect Provider ID.");
            return null;
        }

        try {
            OpenIDConnectProviderRegistry registry = Framework.getService(OpenIDConnectProviderRegistry.class);
            OpenIDConnectProvider provider = registry.getProvider(serviceProviderName);

            if (provider == null) {
                sendError(req, "No service provider called: \"" + serviceProviderName + "\".");
                return null;
            }

            // Check the state token
            if (!Framework.isBooleanPropertyTrue(PROPERTY_SKIP_OAUTH_TOKEN) && !provider.verifyStateToken(req)) {
                sendError(req, "Invalid state parameter.");
            }

            // Validate the token
            String accessToken = getAccessToken(provider, req, code);
            
            if (accessToken == null) {
                return null;
            }

            OpenIDUserInfo info = provider.getUserInfo(accessToken);

            // Store the user info as a key in the request so apps can use it
            // later in the chain
            req.setAttribute(USERINFO_KEY, info);

            UserResolver userResolver = provider.getUserResolver();

            String userId;
            if (Framework.isBooleanPropertyTrue(PROPERTY_OAUTH_CREATE_USER)) {
                userId = userResolver.findOrCreateNuxeoUser(info);
            } else {
                userId = findNuxeoUser(info);
            }

            if (userId == null) {

                sendError(req, "No user found with email: \"" + info.getEmail() + "\".");
                return null;
            }

            return new UserIdentificationInfo(userId, userId);

        } catch (NuxeoException e) {
            log.error("Error while retrieve Identity From OAuth", e);
        }

        return null;
    }
	
    private String getAccessToken(OpenIDConnectProvider provider, HttpServletRequest req, String code) {
    	String accessToken = null;

        HttpResponse response = null;

        try {
            AuthorizationCodeFlow flow = ((NuxeoOAuth2ServiceProvider) oauth2Provider).getAuthorizationCodeFlow();

            String redirectUri = getRedirectUri(provider, req);
            AuthorizationCodeTokenRequest newTokenRequest = flow.newTokenRequest(code).setScopes(null);
            response = newTokenRequest.setRedirectUri(redirectUri).executeUnparsed();
        } catch (IOException e) {
            log.error("Error during OAuth2 Authorization", e);
            return null;
        }

        HttpMediaType mediaType = response.getMediaType();
        if (mediaType != null && "json".equals(mediaType.getSubType())) {
            // Try to parse as json
            try {
                TokenResponse tokenResponse = response.parseAs(TokenResponse.class);
                accessToken = tokenResponse.getAccessToken();
            } catch (IOException e) {
                log.warn("Unable to parse accesstoken as JSON", e);
            }
        } else {
            // Fallback as plain text format
            try {
                String[] params = response.parseAsString().split("&");
                for (String param : params) {
                    String[] kv = param.split("=");
                    if (kv[0].equals("access_token")) {
                        accessToken = kv[1]; // get the token
                        break;
                    }
                }
            } catch (IOException e) {
                log.warn("Unable to parse accesstoken as plain text", e);
            }
        }

        return accessToken;
    }

	private String getRedirectUri(OpenIDConnectProvider p, HttpServletRequest req) {
	    return redirectUriResolver.getRedirectUri(p, req);
	}

	public String findNuxeoUser(OpenIDUserInfo userInfo) {

        try {
            UserManager userManager = Framework.getService(UserManager.class);
            Map<String, Serializable> query = new HashMap<String, Serializable>();
            query.put(userManager.getUserEmailField(), userInfo.getEmail());

            DocumentModelList users = Framework.doPrivileged(() -> userManager.searchUsers(query, null));

            if (users.isEmpty()) {
                return null;
            }

            DocumentModel user = users.get(0);
            return (String) user.getPropertyValue(userManager.getUserIdField());

        } catch (NuxeoException e) {
            log.error("Error while search user in UserManager using email " + userInfo.getEmail(), e);
            return null;
        }
    }
	
}
