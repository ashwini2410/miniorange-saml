package org.miniorange.saml;
import org.acegisecurity.Authentication;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.pac4j.core.client.RedirectAction;
import org.pac4j.core.client.RedirectAction.RedirectType;
import org.pac4j.saml.profile.SAML2Profile;
import org.w3c.dom.Document;
import org.apache.commons.io.IOUtils;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Logger;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import hudson.tasks.Mailer;
public class MoSAMLAddIdp extends SecurityRealm{

    private static final Logger LOGGER = Logger.getLogger(MoSAMLAddIdp.class.getName());
    public static final String MO_SAML_SP_AUTH_URL = "securityRealm/moSamlAuth";
    public static final String MO_SAML_JENKINS_LOGIN_ACTION = "securityRealm/moLoginAction";
    public static final String MO_SAML_SSO_FORCE_STOP = "securityRealm/moSAMLSingleSignOnForceStop";


    private static final String LOGIN_TEMPLATE_PATH = "/templates/mosaml_login_page_template.html";

    private String idpEntityId;
    private String ssoUrl;
    //private String sslUrl;
    private String x509Certificate;
    // Information related to Attribute Mapping
    private String usernameAttribute;
    private String emailAttribute;
    private Boolean userCreate;

    @DataBoundConstructor
    public MoSAMLAddIdp(String idpEntityId,
                        String ssoUrl,
                        String x509Certificate,
                        String usernameAttribute,
                        String emailAttribute,
                        Boolean userCreate
    ) {
        super();
        this.idpEntityId = idpEntityId;
        this.ssoUrl = ssoUrl;
        this.x509Certificate = x509Certificate;
        this.usernameAttribute = "NameID";
        this.emailAttribute = "NameID";
        this.userCreate = userCreate;
        if (StringUtils.isNotEmpty(usernameAttribute)) {
            this.usernameAttribute = usernameAttribute;
        }

        if (StringUtils.isNotEmpty(emailAttribute)) {
            this.emailAttribute = emailAttribute;
        }

        //this.sslUrl = sslUrl;
        try {
            generateIDPMetadataFile();
            generateUserMetadataFile();
        }
        catch (IOException e) {
            LOGGER.fine("Error during generating IDP metadata file");
        }

    }
    @Override
    public String getLoginUrl() {
        return "securityRealm/moLoginAction";
    }
    @Override
    public void doLogout(StaplerRequest req, StaplerResponse rsp) {
        try {

            super.doLogout(req, rsp);
        } catch (ServletException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        return "securityRealm/moLoginAction";
    }

    public HttpResponse doMoLogin(final StaplerRequest request, final StaplerResponse response,String errorMessage)
    {
        return new HttpResponse() {
            public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException, ServletException {
                rsp.setContentType("text/html;charset=UTF-8");
                String html = IOUtils.toString(MoSAMLAddIdp.class.getResourceAsStream(LOGIN_TEMPLATE_PATH), "UTF-8");
                if(StringUtils.isNotBlank(errorMessage))
                {
                    html = html.replace("<input type=\"hidden\" />", errorMessage);
                }
                rsp.getWriter().println(html);
            }
        };
    }


    public  void doMoLoginAction(final StaplerRequest request, final StaplerResponse response) {
        try {
            String username = request.getParameter("j_username");
            String password = request.getParameter("j_password");
          Boolean isValidUser = Boolean.FALSE;
            String error = StringUtils.EMPTY;
            if (StringUtils.isNotBlank(username)) {
                final User user_jenkin = User.getById(username,false);
                if (user_jenkin != null) {
                    try {
                        new MoHudsonPrivateSecurityRealm().authenticate(username, password);
                        isValidUser = Boolean.TRUE;
                    } catch (Exception e) {
                        isValidUser = Boolean.FALSE;
                    }
                    if(isValidUser)
                    {
                        HttpSession session = request.getSession(false);
                        if (session != null) {
                            session.invalidate();
                        }
                        request.getSession(true);
                        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
                        authorities.add(AUTHENTICATED_AUTHORITY);
                        MoSAMLUserInfo userInfo = new MoSAMLUserInfo(username, authorities.toArray(new GrantedAuthority[authorities.size()]));
                        MoSAMLAuthenticationTokenInfo tokenInfo = new MoSAMLAuthenticationTokenInfo(userInfo);
                        SecurityContextHolder.getContext().setAuthentication(tokenInfo);
                        SecurityListener.fireAuthenticated(userInfo);
                        SecurityListener.fireLoggedIn(user_jenkin.getId());
                        response.sendRedirect(getBaseUrl());
                        return;
                    }
                }
                error = "INVALID USER OR PASSWORD";
            }
            String errorMessage = StringUtils.EMPTY;
            if (StringUtils.isNotBlank(error)) {
                errorMessage = "<div class=\"alert alert-danger\">Invalid username or password</div><br>";
            }
            String html = customLoginTemplate(response,errorMessage);
            response.getWriter().println(html);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String customLoginTemplate(StaplerResponse response, String errorMessage) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String html = IOUtils.toString(MoSAMLAddIdp.class.getResourceAsStream(LOGIN_TEMPLATE_PATH), "UTF-8");
        if (StringUtils.isNotBlank(errorMessage)) {
            html = html.replace("<input type=\"hidden\" />", errorMessage);
        }
        return html;
    }
    public  HttpResponse doMoSamlLogin(final StaplerRequest request, final StaplerResponse response) {
        RedirectAction action = null;
        action = new MoSAMLLoginRedirectAction(getMoSAMLPluginSettings(), request, response).get();
        if (RedirectType.SUCCESS == action.getType()) {
            return HttpResponses.literalHtml(action.getContent());
        } else if (RedirectType.REDIRECT == action.getType()) {
            return HttpResponses.redirectTo(action.getLocation());
        } else {
            throw new IllegalStateException("Invalid response" + action.getType());
        }

    }

    private String getBaseUrl() {
        return Jenkins.get().getRootUrl();
    }
    private String getErrorUrl() {
        return Jenkins.get().getRootUrl()+MO_SAML_JENKINS_LOGIN_ACTION;
    }
   private String getUserMetadataFilePath() {
        return jenkins.model.Jenkins.getInstance().getRootDir().getAbsolutePath() + "/jenkins-saml-user-metadata.txt";
    }

    public HttpResponse doMoSAMLSingleSignOnForceStop(final StaplerRequest request, final StaplerResponse response) {
        Jenkins.getInstanceOrNull().setSecurityRealm(new HudsonPrivateSecurityRealm(false));
        return HttpResponses.redirectTo(getBaseUrl());
    }
    @RequirePOST
    public HttpResponse doMoSamlAuth (final StaplerRequest request, final StaplerResponse response) throws IOException {
        String samlResponse = request.getParameter("SAMLResponse");
        MoSAMLPluginSettings settings = getMoSAMLPluginSettings();
        String xmlData = new String(Base64.getDecoder().decode(samlResponse));
        try {
            String username="";
            String email="";
            DocumentBuilderFactory documentBuilderFactory=DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder db = documentBuilderFactory.newDocumentBuilder();
            InputSource is = new InputSource();
            is.setCharacterStream(new StringReader(xmlData));
            Document doc = db.parse(is);
            NodeList node1 = doc.getElementsByTagNameNS("*","Subject");
            for(int i=0; i<node1.getLength(); i++)
            {
                Node User_Node = node1.item(i);
                if(User_Node.getNodeType() == Node.ELEMENT_NODE)
                {
                    Element UserNameElement = (Element) User_Node;
                 username = UserNameElement.getElementsByTagNameNS("*","NameID").item(0).getTextContent();
                     LOGGER.fine(username);
                }
            }
            NodeList node2 = doc.getElementsByTagNameNS("*","AttributeStatement");
            for(int i=0; i<node2.getLength(); i++)
            {
                Node Email_Node = node2.item(i);
                if(Email_Node.getNodeType() == Node.ELEMENT_NODE)
                {
                    Element studentElement1 = (Element) Email_Node;
                   email= studentElement1.getElementsByTagNameNS("*","Attribute").item(0).getTextContent();
                     LOGGER.fine(email);

                }
            }
            if (StringUtils.isNotBlank(username)) {
                User user = User.getById(username, false);
                if (user != null) {
                    HttpSession session = request.getSession(false);
                    if (session != null) {
                        session.invalidate();
                    }
                    request.getSession(true);
                    List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
                    authorities.add(AUTHENTICATED_AUTHORITY);
                    MoSAMLUserInfo userInfo = new MoSAMLUserInfo(username, authorities.toArray(new GrantedAuthority[authorities.size()]));
                    MoSAMLAuthenticationTokenInfo tokenInfo = new MoSAMLAuthenticationTokenInfo(userInfo);
                    SecurityContextHolder.getContext().setAuthentication(tokenInfo);
                    SecurityListener.fireAuthenticated(userInfo);
                    SecurityListener.fireLoggedIn(user.getId());
                    return HttpResponses.redirectTo(getBaseUrl());
                } else {
                    try {
                        if(settings.getUserCreate()){
                            File file = new File( getUserMetadataFilePath());
                            Path p = Paths.get(getUserMetadataFilePath());
                            Files.setAttribute(p, "dos:hidden", false);
                            if(file.exists())
                            {
                                Scanner scanner = new Scanner(file);
                                int noOfUsers=10;
                                while(scanner.hasNextInt())
                                {
                                    noOfUsers = scanner.nextInt();
                                }
                                scanner.close();
                            if(noOfUsers<=9) {
                                User new_user=User.getById(username, true);
                                new_user.addProperty(new Mailer.UserProperty(email));
                                HttpSession session = request.getSession(false);
                                if (session != null) {
                                    session.invalidate();}
                                request.getSession(true);
                                List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
                                authorities.add(AUTHENTICATED_AUTHORITY);
                                MoSAMLUserInfo userInfo = new MoSAMLUserInfo(username, authorities.toArray(new GrantedAuthority[authorities.size()]));
                                MoSAMLAuthenticationTokenInfo tokenInfo = new MoSAMLAuthenticationTokenInfo(userInfo);
                                SecurityContextHolder.getContext().setAuthentication(tokenInfo);
                                SecurityListener.fireAuthenticated(userInfo);
                                SecurityListener.fireLoggedIn(new_user.getId());
                                {
                                    FileWriter fr = new FileWriter(file, false);
                                    BufferedWriter br = new BufferedWriter(fr);
                                    br.write(String.valueOf(noOfUsers+1));
                                    br.close();
                                    fr.close();
                                    Files.setAttribute(p, "dos:hidden", true);
                                    return HttpResponses.redirectTo(getBaseUrl());
                                   }

                            }
                            else {
                                String errorMessage = "<div class=\"alert alert-danger\">Upgrade to Premium</div><br>";
                                return doMoLogin(request, response,errorMessage);}
                            }
                            else {
                                String errorMessage = "<div class=\"alert alert-danger\">Invalid username</div><br>";
                                return doMoLogin(request, response,errorMessage);
                            }
                        } else {
                            String errorMessage = "<div class=\"alert alert-danger\">User creation not allowed!</div><br>";
                            return doMoLogin(request, response,errorMessage);
                        }
                    } catch (Exception ex) {
                    ex.printStackTrace();
                        String errorMessage = "<div class=\"alert alert-danger\">Error occurred .Please contact administrator.</div><br>";
                        return doMoLogin(request, response,errorMessage);
                    }
                }
            } else {
                String errorMessage = "<div class=\"alert alert-danger\">Username is blank.</div><br>";
                return doMoLogin(request, response,errorMessage);
            }
        } catch (Exception ex) {
            String errorMessage = "<div class=\"alert alert-danger\">Response is invalid.</div><br>";
            return doMoLogin(request, response,errorMessage);
        }
    }

    private List<GrantedAuthority> getGrantedAuthorities(SAML2Profile saml2Profile) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(AUTHENTICATED_AUTHORITY);
        return authorities;
    }

    private void createSession(StaplerRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        request.getSession(true);
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {

            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof MoSAMLAuthenticationTokenInfo) {
                    return authentication;
                }
                throw new BadCredentialsException("Invalid Auth type " + authentication);
            }

        });
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public String getSsoUrl() {
        return ssoUrl;
    }

    public String getX509Certificate() {
        return x509Certificate;
    }

    public String getUsernameAttribute() {
        if (StringUtils.isEmpty(usernameAttribute)) {
            return "NameID";
        } else {
            return usernameAttribute;
        }
    }

    public String getEmailAttribute() {
        if (StringUtils.isEmpty(emailAttribute)) {
            return "NameID";
        } else {
            return emailAttribute;
        }
    }

   /* public String getSslUrl() {
        return sslUrl;
    }*/
    public boolean getUserCreate() {
        return userCreate;
    }

    private MoSAMLPluginSettings getMoSAMLPluginSettings()  {
        MoSAMLPluginSettings settings = new MoSAMLPluginSettings(idpEntityId, ssoUrl, x509Certificate, usernameAttribute, emailAttribute,userCreate,0);
        return  settings;
    }

    static String getIDPMetadataFilePath() {
        return jenkins.model.Jenkins.getInstance().getRootDir().getAbsolutePath() + "/jenkins-saml-idp-metadata.xml";
    }


    static String getSPMetadataFilePath() {
        return jenkins.model.Jenkins.getInstance().getRootDir().getAbsolutePath() + "/jenkins-saml-sp-metadata.xml";
    }

    public void generateIDPMetadataFile() throws IOException {
        try {
            String xml = getXmlFormattedString();
            if (StringUtils.isNotEmpty(xml)) {
                FileUtils.writeStringToFile(new File(getIDPMetadataFilePath()), xml);
            }
        } catch (IOException e) {
            throw new IOException("Can not write Jenkins File", e);
        }
    }
    public void generateUserMetadataFile() throws IOException {
        try {
            File file =new File(getUserMetadataFilePath());
            if (!file.exists()) {
                FileWriter fr = new FileWriter(file, true);
                BufferedWriter br = new BufferedWriter(fr);
                br.write("0");
                br.close();
                fr.close();
                file.setWritable(true);
                Path p = Paths.get(getUserMetadataFilePath());
                Files.setAttribute(p, "dos:hidden", true);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getXmlFormattedString() {
        String xml;
        /*if (StringUtils.isNotEmpty(sslUrl)) {
            xml = "<md:EntityDescriptor entityID=\"##ENTITYID##\" ID=\"_58eb6efc-1f19-431b-8146-3fef71f908d0\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"##AUTHNREQUESTSIGNED##\"><md:KeyDescriptor use=\"signing\"><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>##SIGNATURE##</X509Certificate></X509Data></KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"##SSOURL##\" /><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"##SSOURL##\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"##SLOURL##\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"##SLOURL##\"/></md:IDPSSODescriptor></md:EntityDescriptor>";
        }*/  {
            xml = "<md:EntityDescriptor entityID=\"##ENTITYID##\" ID=\"_58eb6efc-1f19-431b-8146-3fef71f908d0\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"##AUTHNREQUESTSIGNED##\"><md:KeyDescriptor use=\"signing\"><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>##SIGNATURE##</X509Certificate></X509Data></KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"##SSOURL##\" /><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"##SSOURL##\"/></md:IDPSSODescriptor></md:EntityDescriptor>";
        }
        xml = xml.replace("##ENTITYID##", getIdpEntityId());
        xml = xml.replace("##AUTHNREQUESTSIGNED##", "false");
        xml = xml.replace("##SIGNATURE##", getX509Certificate());
        xml = xml.replace("##SSOURL##", getSsoUrl());
        //xml = xml.replace("##SLOURL##", getSslUrl());
        return xml;
    }
  @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }

        @Override
        public String getDisplayName() {
            return "miniOrange SAML 2.0";
        }

        public FormValidation doCheckIdpEntityId(@QueryParameter String idpEntityId) {
            if (StringUtils.isEmpty(idpEntityId)) {
                return FormValidation.ok();
            }
            try {
                new URL(idpEntityId);
            } catch (MalformedURLException e) {
                return FormValidation.error("The url is malformed.", e);
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckSsoUrl(@QueryParameter String ssoUrl) {
            if (StringUtils.isEmpty(ssoUrl)) {
                return FormValidation.ok();
            }
            try {
                new URL(ssoUrl);
            } catch (MalformedURLException e) {
                return FormValidation.error("The url is malformed.", e);
            }
            return FormValidation.ok();
        }

     /*   public FormValidation doCheckSsLUrl(@QueryParameter String sslUrl) {
            if (StringUtils.isEmpty(sslUrl)) {
                return FormValidation.ok();
            }
            try {
                new URL(sslUrl);
            } catch (MalformedURLException e) {
                return FormValidation.error("The url is malformed.", e);
            }
            return FormValidation.ok();
        }*/

        public FormValidation doCheckX509Certificate(@QueryParameter String x509Certificate) {
            if (StringUtils.isEmpty(x509Certificate)) {
                return FormValidation.ok();
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckUsernameAttribute(@QueryParameter String usernameAttribute) {
            if (StringUtils.isEmpty(usernameAttribute)) {
                return FormValidation.warning("Username Can not kept blank");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckEmailAttribute(@QueryParameter String emailAttribute) {
            if (StringUtils.isEmpty(emailAttribute)) {
                return FormValidation.warning("Email Address Can not kept blank");
            }
            return FormValidation.ok();
        }

    }
}
