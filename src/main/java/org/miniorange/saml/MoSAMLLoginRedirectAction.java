package org.miniorange.saml;

import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.pac4j.core.client.RedirectAction;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.saml.client.SAML2Client;
import java.util.logging.Logger;
public class MoSAMLLoginRedirectAction extends MoSAMLRedirectActionWrapper<RedirectAction>{
    private static final Logger LOGGER = Logger.getLogger(MoSAMLLoginRedirectAction.class.getName());

    public MoSAMLLoginRedirectAction(MoSAMLPluginSettings settings, StaplerRequest request, StaplerResponse response) {
        this.settings = settings;
        this.request = request;
        this.response = response;
    }

    @Override
    protected RedirectAction perform() throws IllegalStateException{
        try {
            SAML2Client client = getSAML2Client();
            WebContext context = getWebContext();
            return client.getRedirectAction(context);
        } catch (HttpAction action) {
            throw new IllegalStateException(action);
        }
    }
}
