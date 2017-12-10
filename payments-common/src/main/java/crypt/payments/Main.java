package crypt.payments;

import com.google.gson.Gson;
import crypt.payments.certificates.Certificate;
import crypt.payments.signatures.SignatureUtils;
import crypt.payments.signatures.rsa.RSAKeyFactory;
import crypt.payments.signatures.rsa.RSAKeyPair;
import crypt.payments.signatures.rsa.RSAPrivateKey;
import crypt.payments.signatures.rsa.RSAPublicKey;
import crypt.payments.utils.GsonFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.time.LocalDateTime;
import java.time.Month;

public class Main {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
    }

    public static void newBrokerCertificate() {

        RSAKeyPair keyPair = RSAKeyFactory.generateKeyPair(512);
        RSAPublicKey publicKey = keyPair.getPublicKey();
        RSAPrivateKey privateKey = keyPair.getPrivateKey();

        Certificate certificate = new Certificate();
        certificate.setSubjectName("Lab_N3_Broker");
        certificate.setExpirationDate(LocalDateTime.of(2017, Month.DECEMBER.getValue(), 31, 23, 59));
        certificate.setPublicKey(publicKey);

        SignatureUtils.sign(certificate, privateKey);

        Gson gson = GsonFactory.createGson();

        System.out.println(gson.toJson(certificate));
        System.out.println(gson.toJson(privateKey));
    }
}
