package crypt.ssl.testing;

import crypt.ssl.utils.CertificateDecoder;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.x509.PKIXCertPathReviewer;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class CertificateTest {

    public static final String CA_CERTS = "C:\\Program Files\\Java\\jdk1.8.0_73\\jre\\lib\\security\\cacerts";

    public static void main(String[] args) throws Exception {
        //bcValidation(getX509Certificates());
        //jceCertPathBuilding(getX509Certificates());
        jceCertPathValidation(getX509Certificates());
    }

    private static void jceCertPathBuilding(List<X509Certificate> chain) throws Exception {
        Collection<X509CRL> crls = Collections.emptyList();

        X509CertSelector target = new X509CertSelector();
        target.setCertificate(chain.get(0));

        PKIXBuilderParameters params = new PKIXBuilderParameters(caCerts(), target);
        params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(chain)));
        params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls)));
        params.setRevocationEnabled(false);

        CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX");
        PKIXCertPathBuilderResult r = (PKIXCertPathBuilderResult) pathBuilder.build(params);

        CertPath certPath = r.getCertPath();
    }

    private static void jceCertPathValidation(List<X509Certificate> chain) throws Exception {
        //X509Certificate certToVerify = chain.get(0);

        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        CertPath cp = cf.generateCertPath(chain);

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
        PKIXParameters pkixParams = new PKIXParameters(caCerts());
        pkixParams.setRevocationEnabled(false);

        cpv.validate(cp, pkixParams);
    }

    private static void bcValidation(List<X509Certificate> certificates) throws Exception {
        CertificateFactory factory = new CertificateFactory();
        CertPath certPath = factory.engineGenerateCertPath(certificates);

        PKIXParameters parameters = new PKIXParameters(caCerts());
        parameters.setRevocationEnabled(false);

        PKIXCertPathReviewer validator = new PKIXCertPathReviewer();
        validator.init(certPath, parameters);

        for (List<ErrorBundle> list : validator.getErrors()) {
            for (ErrorBundle errorBundle : list) {
                System.out.println(errorBundle);
            }

            System.out.println("---------------------------------------------------------------");
        }
    }

    private static List<X509Certificate> getX509Certificates() throws IOException {
        return getCertificates()
                .stream()
                .map(CertificateTest::decode)
                .collect(Collectors.toList());
    }

    private static List<byte[]> getCertificates() throws IOException {
        final int N = 3;
        List<byte[]> certs = new ArrayList<>();

        for (int i = 0; i < N; i++) {
            Path certPath = Paths.get("D:/work_dir/ssl/cert" + i + ".crt");
            byte[] certBytes = Files.readAllBytes(certPath);

            certs.add(certBytes);
        }

        return certs;
    }

    private static X509Certificate decode(byte[] certBytes) {
        try {
            return CertificateDecoder.decodeCertificate(certBytes);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyStore caCerts() {
        try {
            return HttpComponentsTest.loadKeyStore(new File(CA_CERTS), "changeit");
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
