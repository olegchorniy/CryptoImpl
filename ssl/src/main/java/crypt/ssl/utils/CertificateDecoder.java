package crypt.ssl.utils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public abstract class CertificateDecoder {

    private CertificateDecoder() {
    }

    public static X509Certificate decodeCertificate(byte[] certificateBytes) throws CertificateException {
        return parseCertificate(new ByteArrayInputStream(certificateBytes));
    }

    public static X509Certificate parseCertificate(InputStream is) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("x509");
        return (X509Certificate) certificateFactory.generateCertificate(is);
    }
}
