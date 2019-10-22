package org.miniorange.saml;

import jenkins.model.Jenkins;

import java.util.logging.Logger;

public class MoSAMLPluginSettings {

    private String idpEntityId;
    private String ssoUrl;
    //private String sslUrl;
    private String x509Certificate;
    // Information related to Attribute Mapping
    private String usernameAttribute;
    private String emailAttribute;
   private final Boolean userCreate;
   private int noOfUsers=0;
    public MoSAMLPluginSettings (String idpEntityId, String ssoUrl, String x509Certificate, String usernameAttribute, String emailAttribute,Boolean userCreate,int noOfUsers) {
        this.idpEntityId = idpEntityId;
        this.ssoUrl = ssoUrl;
        //this.sslUrl = sslUrl;
        this.x509Certificate = x509Certificate;
        this.usernameAttribute = usernameAttribute;
        this.emailAttribute = emailAttribute;
        this.userCreate = (userCreate != null) ? userCreate : false;
        this.noOfUsers=noOfUsers;
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public String getSsoUrl() {
        return ssoUrl;
    }

   /* public String getSslUrl() {
        return sslUrl;
    }*/

    public String getX509Certificate() {
        return x509Certificate;
    }

    public String getUsernameAttribute() {
        return usernameAttribute;
    }

    public String getEmailAttribute() {
        return emailAttribute;
    }


    public String getSPBaseUrl() {
        return Jenkins.getInstance().getRootUrl();
    }

    public String getSpAcsUrl() {
        return getSPBaseUrl() + "securityRealm/moSamlAuth";
    }

     public Boolean getUserCreate() {
        return userCreate;
    }

}
