package org.miniorange.saml;

import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.client.SAML2ClientConfiguration;

import java.util.logging.Logger;

public abstract class MoSAMLRedirectActionWrapper<T> {
    private static final Logger LOGGER = Logger.getLogger(MoSAMLRedirectActionWrapper.class.getName());
    private static final MoSAMLKeyStore samlKeyStore = new MoSAMLKeyStore();

    protected StaplerRequest request;
    protected StaplerResponse response;
    protected MoSAMLPluginSettings settings;

    abstract protected T perform();

    public T get() {
        T value = null;
        try {
            //LOGGER.fine("get method is called");
            Thread thread = Thread.currentThread();
            ClassLoader loader = thread.getContextClassLoader();
            thread.setContextClassLoader(InitializationService.class.getClassLoader());
            try {
                InitializationService.initialize();
                value = perform();
            } finally {
                thread.setContextClassLoader(loader);
            }
        } catch (InitializationException e) {
            //LOGGER.fine("Failed to initialize SAML request");
            throw new IllegalStateException(e);
        }
        return value;
    }

    protected WebContext getWebContext() {
        //LOGGER.fine("request = "+request);
       // LOGGER.fine("response = "+response);
        return new J2EContext(request, response);
    }

    protected SAML2Client getSAML2Client() {
        //LOGGER.fine("getSAML2Client is called");
        SAML2ClientConfiguration configuration = new SAML2ClientConfiguration();
        configuration.setDestinationBindingType("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        configuration.setIdentityProviderMetadataResource(new MoSAMLIdpMetadataResource(MoSAMLAddIdp.getIDPMetadataFilePath()));
        configuration.setMaximumAuthenticationLifetime(5 * 60 * 60);
        configuration.setForceServiceProviderMetadataGeneration(true);
        configuration.setServiceProviderMetadataResource(new MoSAMLIdpMetadataResource(MoSAMLAddIdp.getSPMetadataFilePath()));


        if (!samlKeyStore.isValid()) {
            samlKeyStore.init();
        }

        configuration.setKeystorePath(samlKeyStore.getKeystorePath());
        configuration.setKeystorePassword(samlKeyStore.getKeystorePassword());
        configuration.setPrivateKeyPassword(samlKeyStore.getKeystorePrivateKeyPassword());
        configuration.setKeystoreAlias(samlKeyStore.getKeystoreAlias());

        SAML2Client saml2Client = new SAML2Client(configuration);
        saml2Client.setCallbackUrl(settings.getSpAcsUrl());
        saml2Client.init(getWebContext());

        //LOGGER.fine("SP Metadata : "+saml2Client.getServiceProviderMetadataResolver().getMetadata());

        return saml2Client;
    }
}
