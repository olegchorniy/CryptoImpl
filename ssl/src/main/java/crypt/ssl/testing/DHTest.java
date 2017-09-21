package crypt.ssl.testing;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyAgreement;
import java.security.Security;

public class DHTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("DH", "BC");

        System.out.println(agreement);
    }
}
