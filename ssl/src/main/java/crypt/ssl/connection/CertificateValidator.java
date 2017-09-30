package crypt.ssl.connection;

import crypt.ssl.Constants;
import crypt.ssl.TlsExceptions;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.List;

public class CertificateValidator {

    public void validate(List<X509Certificate> chain) throws IOException {
        try {
            CertPath certPath = toCertPath(chain);
            PKIXParameters parameters = getValidationParameters();

            CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");

            validator.validate(certPath, parameters);
        } catch (GeneralSecurityException e) {
            throw TlsExceptions.badCertificate(e);
        }
    }

    private PKIXParameters getValidationParameters() throws IOException, GeneralSecurityException {
        PKIXParameters parameters = new PKIXParameters(rootCACertificates());
        // disable CRLs/OCSP checking for simplicity
        parameters.setRevocationEnabled(false);

        return parameters;
    }

    private static CertPath toCertPath(List<X509Certificate> certificates) throws GeneralSecurityException {
        return CertificateFactory.getInstance("X.509", "BC").generateCertPath(certificates);
    }

    /**
     * Returns keystore with java's trusted root CA certificates.
     */
    private static KeyStore rootCACertificates() throws IOException {
        try (InputStream certs = new FileInputStream(new File(Constants.CA_CERTS))) {

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(certs, "changeit".toCharArray());

            return trustStore;
        } catch (Exception e) {
            throw TlsExceptions.internalError(e);
        }
    }
}
