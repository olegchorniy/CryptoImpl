package crypt.payments.signatures.rsa;

import lombok.SneakyThrows;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public abstract class RSAKeyFactory {

    private RSAKeyFactory() {
    }

    @SneakyThrows
    public static RSAKeyPair generateKeyPair(int keySize) {
        /* Generate key pair */
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(keySize);

        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        /* Convert to the spec representation */
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);

        /* Convert to the representation used in our code */
        BigInteger n = privateKeySpec.getModulus();
        BigInteger d = privateKeySpec.getPrivateExponent();
        BigInteger e = publicKeySpec.getPublicExponent();

        return new RSAKeyPair(
                new RSAPublicKey(n, e),
                new RSAPrivateKey(n, d)
        );
    }
}
