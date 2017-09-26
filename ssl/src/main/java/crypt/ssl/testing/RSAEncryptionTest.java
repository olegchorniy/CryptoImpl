package crypt.ssl.testing;

import crypt.ssl.cipher.CipherFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;

public class RSAEncryptionTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

        /*KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        keyFactory.generatePublic(new RSAPublicKeySpec());*/

        /*Cipher rsa = CipherFactory.getInstance("RSA/PKCS1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, );*/
    }
}
