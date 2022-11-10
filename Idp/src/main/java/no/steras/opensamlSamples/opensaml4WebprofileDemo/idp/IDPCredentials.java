package no.steras.opensamlSamples.opensaml4WebprofileDemo.idp;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

public class IDPCredentials {
    private static String publicKeyFile = "C:\\apache-tomcat-9.0.67\\New folder\\certificates\\idpPublic.pem";
    private static String privateKeyFile = "C:\\apache-tomcat-9.0.67\\New folder\\certificates\\idpPrivate.der";
    private static String SPPublicKeyFile = "C:\\apache-tomcat-9.0.67\\New folder\\certificates\\spPublic.pem";

    private static final Credential credential;

    static {
        try {
            credential = CredentialSupport.getSimpleCredential(
                    getPublicKey(publicKeyFile),
                    getPrivateKey(privateKeyFile));
        } catch (Exception e) {
            throw new RuntimeException("Something went wrong reading credentials", e);
        }
    }

    public static PrivateKey getPrivateKey(String filename) throws Exception {

        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static PublicKey getPublicKey(String filename) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(filename);
        X509Certificate cer = (X509Certificate) certFactory.generateCertificate(is);
        return cer.getPublicKey();
    }

    public static Credential getSPublicKeyCredential() throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(SPPublicKeyFile);
        X509Certificate cer = (X509Certificate) certFactory.generateCertificate(is);
        return CredentialSupport.getSimpleCredential(cer.getPublicKey(), null);
    }

    public static Credential getCredential() {
        return credential;
    }
}