package crypt.ssl.testing;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public abstract class RSAKeyDecoding {

    private RSAKeyDecoding() {
    }

    public static X509Certificate parseCertificate(InputStream is) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("x509");
        return (X509Certificate) certificateFactory.generateCertificate(is);
    }

    private static RSAPublicKey decodePublicKey(String encodedPublicKey) throws GeneralSecurityException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(parseBase64(encodedPublicKey));

        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(keySpec);
    }

    private static RSAPrivateKey decodePrivateKey(String encodedPrivateKey) throws GeneralSecurityException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(parseBase64(encodedPrivateKey));

        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(keySpec);
    }

    private static String encodeBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] parseBase64(String base64Bytes) {
        return Base64.getDecoder().decode(base64Bytes);
    }
}
