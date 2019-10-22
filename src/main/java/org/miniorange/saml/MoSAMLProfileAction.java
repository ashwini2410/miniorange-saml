package org.miniorange.saml;

import org.acegisecurity.BadCredentialsException;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.credentials.SAML2Credentials;
import org.pac4j.saml.exceptions.SAMLException;
import org.pac4j.saml.profile.SAML2Profile;

import java.util.logging.Logger;

public class MoSAMLProfileAction extends MoSAMLRedirectActionWrapper<SAML2Profile>{
    private static final Logger LOGGER = Logger.getLogger(MoSAMLProfileAction.class.getName());

    public MoSAMLProfileAction(MoSAMLPluginSettings settings, StaplerRequest request, StaplerResponse response) {
        this.settings = settings;
        this.request = request;
        this.response = response;
    }

    @Override
    protected SAML2Profile perform() {
        SAML2Credentials credentials;
        SAML2Profile saml2Profile;
        try {
            final SAML2Client client = getSAML2Client();
            final WebContext context = getWebContext();
            credentials = client.getCredentials(context);
            saml2Profile = client.getUserProfile(credentials, context);
        } catch (HttpAction | SAMLException e) {

            throw new BadCredentialsException(e.getMessage(), e);
        }
        if (saml2Profile == null) {
            String msg = "Could not find user profile for SAML: " + credentials;
            throw new BadCredentialsException(msg);
        }
        return saml2Profile;
    }
}
