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
        //LOGGER.fine("MoSAMLProfileAction.perform method is called");
        SAML2Credentials credentials;
        SAML2Profile saml2Profile;
        try {
           // LOGGER.fine("1");
            final SAML2Client client = getSAML2Client();
           // LOGGER.fine("2 = "+client.getName());
            final WebContext context = getWebContext();
           // LOGGER.fine("3");
            credentials = client.getCredentials(context);
            //LOGGER.fine("4");
            saml2Profile = client.getUserProfile(credentials, context);
            //LOGGER.fine("5");
        } catch (HttpAction | SAMLException e) {
           // LOGGER.fine("Exception = "+e);
            throw new BadCredentialsException(e.getMessage(), e);
        }
        if (saml2Profile == null) {
            String msg = "Could not find user profile for SAML: " + credentials;
            //LOGGER.fine(msg);
            throw new BadCredentialsException(msg);
        }

       // LOGGER.fine("saml2Profile.toString() = "+saml2Profile.toString());
        return saml2Profile;
    }
}
