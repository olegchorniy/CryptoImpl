package crypt.ssl.testing;

import crypt.ssl.utils.Dumper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.*;

public class DHTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
    }

    public static void dhExample() throws Exception {
        KeyPair keyPair = newDHKeyPair(512);

        DHPrivateKeySpec privateKeySpec = toKeySpec(keyPair.getPrivate());
        DHPublicKeySpec publicKeySpec = toKeySpec(keyPair.getPublic());

        BigInteger g = publicKeySpec.getG();
        BigInteger p = publicKeySpec.getP();

        KeyPair peerKeyPair = peerKeyPair(new DHParameterSpec(p, g));
        DHPrivateKeySpec peerPrivateKeySpec = toKeySpec(peerKeyPair.getPrivate());

        BigInteger xA = privateKeySpec.getX();
        BigInteger xB = peerPrivateKeySpec.getX();

        System.out.println("p = " + p);
        System.out.println("g = " + g);
        System.out.println("xA = " + xA);
        System.out.println("xB = " + xB);

        System.out.println("Homegrown DH");
        Dumper.dumpToStdout(commonKey(p, g, xA, xB));

        System.out.println("JCA DH V1");
        Dumper.dumpToStdout(generateCommonSecret(keyPair.getPrivate(), peerKeyPair.getPublic()));

        System.out.println("JCA DH V2");
        Dumper.dumpToStdout(generateCommonSecret(peerKeyPair.getPrivate(), keyPair.getPublic()));
    }

    private static KeyPair newDHKeyPair(int strength) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGenerator.initialize(strength);

        return keyPairGenerator.generateKeyPair();
    }

    private static KeyPair peerKeyPair(DHParameterSpec dhParams) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGenerator.initialize(dhParams);

        return keyPairGenerator.generateKeyPair();
    }

    private static DHPrivateKeySpec toKeySpec(PrivateKey privateKey) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");
        return keyFactory.getKeySpec(privateKey, DHPrivateKeySpec.class);
    }

    private static DHPublicKeySpec toKeySpec(PublicKey publicKey) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");
        return keyFactory.getKeySpec(publicKey, DHPublicKeySpec.class);
    }

    /* -------------------------- Homegrown version --------------------------- */

    public static byte[] commonKey(BigInteger p, BigInteger g, BigInteger xA, BigInteger xB) {
        return BigIntegers.asUnsignedByteArray(g.modPow(xA, p).modPow(xB, p));
    }

    public static byte[] generateCommonSecret(PrivateKey privateKey, PublicKey receivedPublicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", "BC");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);

            return keyAgreement.generateSecret();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
