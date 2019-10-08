package org.miniorange.saml;

import hudson.XmlFile;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.apache.commons.lang.math.NumberUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import static java.util.logging.Level.WARNING;

public class MoSAMLKeyStore {
    private static final Logger LOGGER = Logger.getLogger(MoSAMLKeyStore.class.getName());
    public static final String MO_KEYSTORE_PASSWORD = "mo-keystore-password";
    public static final String MO_KEYSTORE_PATH = "resource:samlKeystore.jks";
    public static final String MO_KEYSTORE_TEMP_ALIAS = "mo-keystore-temp";
    public static final String MO_KEYSTORE_ALIAS = "mo-keystore-alias";
    public static final String MO_KEYSTORE_DEFAULT_KEY_ALIAS = "SAML-generated-keyPair";
    public static final String KEY_ALG = "RSA";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final String PROVIDER = "BC";
    public static final String KEY_VALIDITY_PROPERTY = MoSAMLKeyStore.class.getName() + ".validity";
    public static final Long KEY_VALIDITY = 365L;

    public static final String MO_SAML_JENKINS_KEYSTORE_XML = "mo-jenkins-saml-keystore.xml";
    public static final String MO_SAML_JENKINS_KEYSTORE_JKS = "mo-jenkins-saml-keystore.jks";

    private String keystorePath = MO_KEYSTORE_PATH;
    private Secret keystorePassword =  Secret.fromString(MO_KEYSTORE_PASSWORD);
    private Secret keystorePrivateKeyPassword =  Secret.fromString(MO_KEYSTORE_PASSWORD);
    private String keystoreAlias = MO_KEYSTORE_TEMP_ALIAS;
    private Date dateValidity;
    private File keystore;

    private transient XmlFile config = null;

    public MoSAMLKeyStore(){
        Jenkins jenkins = Jenkins.getInstance();
        File file = jenkins.getRootDir();
        File configFile = new File(file, MO_SAML_JENKINS_KEYSTORE_XML);
        config = new XmlFile(configFile);
        try {
            if (config.exists()) {
                config.unmarshal(this);
            }
        } catch (IOException e) {
            LOGGER.log(WARNING, "Failed to write conf file"
                    + config.getFile().getAbsolutePath(), e);
        }
    }

    public synchronized void init() {
        try {
            if (keystore == null) {
                String jenkinsHome = jenkins.model.Jenkins.getInstance().getRootDir().getPath();
                keystore = java.nio.file.Paths.get(jenkinsHome, MO_SAML_JENKINS_KEYSTORE_JKS).toFile();
                keystorePath = "file:" + keystore.getPath();
            }

            if (MO_KEYSTORE_PATH.equals(keystorePassword.getPlainText())) {
                keystorePassword = Secret.fromString(generatePassword());
                keystorePrivateKeyPassword = Secret.fromString(generatePassword());
            }
            keystoreAlias = MO_KEYSTORE_ALIAS;
            KeyStore keyStore = loadKeyStore(keystore,keystorePassword.getPlainText());
            KeyPair keypair = getKeyPair(2048);
            X509Certificate[] chain = createCertificateChain(keypair);
            keyStore.setKeyEntry(keystoreAlias, keypair.getPrivate(), keystorePrivateKeyPassword.getPlainText().toCharArray(), chain);
            saveKeyStore(keystore, keyStore, keystorePassword.getPlainText());
            try {
                config.write(this);
            } catch (IOException e) {
                LOGGER.log(WARNING, "It is not possible to write the configuration file "
                        + config.getFile().getAbsolutePath(), e);
            }
        } catch (Exception e) {
            keystorePassword = Secret.fromString(MO_KEYSTORE_PASSWORD);
            keystorePrivateKeyPassword =  Secret.fromString(MO_KEYSTORE_PASSWORD);
            keystorePath = MO_KEYSTORE_PATH;
            keystoreAlias = MO_KEYSTORE_ALIAS;
        }
    }

    private String generatePassword() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte bytes[] = new byte[256];
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private KeyStore loadKeyStore(File keystore, String password)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = new FileInputStream(keystore)) {
            keyStore.load(in, password.toCharArray());
        } catch (IOException e) {
            keyStore = initKeyStore(keystore, password);
        }
        return keyStore;
    }

    private KeyStore initKeyStore(File keystore, String password)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, password.toCharArray());
        saveKeyStore(keystore, keyStore, password);
        return keyStore;
    }

    private void saveKeyStore(File keystore, KeyStore keyStore, String password)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        try (FileOutputStream fos = new FileOutputStream(keystore)){
            keyStore.store(fos, password.toCharArray());
        }
    }

    private KeyPair getKeyPair(int keySize) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALG, PROVIDER);
        SecureRandom prng = new SecureRandom();
        keyGen.initialize(keySize, prng);
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }

    private X509Certificate[] createCertificateChain(KeyPair keypair)
            throws IOException, CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
        X509Certificate[] chain = new X509Certificate[1];
        Long validity = NumberUtils.toLong(System.getProperty(KEY_VALIDITY_PROPERTY), KEY_VALIDITY);
        chain[0] = generateCertificate("cn=SAML-jenkins", new Date(),  TimeUnit.DAYS.toSeconds(validity), keypair);
        return chain;
    }

    private X509Certificate generateCertificate(String dnName, Date notBefore, long validity, KeyPair keyPair)
            throws CertIOException, OperatorCreationException, CertificateException, NoSuchAlgorithmException {

        X500Name dn = new X500Name(dnName);
        Date notAfter = new Date(notBefore.getTime() + validity * 1000L);
        dateValidity = notAfter;
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn,
                new BigInteger(160, new SecureRandom()),
                notBefore,
                notAfter,
                dn,
                keyPair.getPublic()
        );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

        ASN1Encodable[] subjectAltNAmes = {new GeneralName(GeneralName.dNSName, dnName)};
        builder.addExtension(Extension.subjectAlternativeName, false,
                GeneralNames.getInstance(new DERSequence(subjectAltNAmes)));

        X509CertificateHolder certHldr = builder.build(
                new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.getPrivate()));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHldr);

        return cert;
    }

    private boolean keystoreFileExists() {
        return keystore != null  && keystore.exists() && keystore.canRead();
    }

    public synchronized boolean isValid() {
        boolean notExpired = false;
        boolean fileExists = keystoreFileExists();
        boolean keysExists = false;

        if (dateValidity != null) {
            Calendar validity = Calendar.getInstance();
            validity.setTime(dateValidity);
            notExpired = Calendar.getInstance().compareTo(validity) <= 0;
        }
        if(fileExists) {
            try {
                KeyStore ks = loadKeyStore(keystore, keystorePassword.getPlainText());
                keysExists = ks.getKey(keystoreAlias, keystorePrivateKeyPassword.getPlainText().toCharArray()) != null;
            } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException
                    | UnrecoverableKeyException e) {
                LOGGER.log(WARNING, "THe keystore is not accessible", e);
                keysExists = false;
            }
        }
        return notExpired && fileExists && keysExists;
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public String getKeystorePassword() {
        return keystorePassword.getPlainText();
    }

    public String getKeystorePrivateKeyPassword() {
        return keystorePrivateKeyPassword.getPlainText();
    }

    public String getKeystoreAlias() {
        return keystoreAlias;
    }

    public Date getDateValidity() {
        return dateValidity;
    }

    public File getKeystore() {
        return keystore;
    }

    public XmlFile getConfig() {
        return config;
    }
}
