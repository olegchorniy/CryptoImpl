package crypt.payments.signatures;

import crypt.payments.certificates.Certificate;
import crypt.payments.signatures.rsa.RSAPrivateKey;
import crypt.payments.signatures.rsa.RSAPublicKey;
import lombok.SneakyThrows;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public abstract class SignatureUtils {

    public static final String HASH_ALGORITHM = "SHA1";

    private SignatureUtils() {
    }

    @SneakyThrows
    public static void sign(SignedData signedData, RSAPrivateKey key) {
        Signature signer = getInstance();
        initSign(signer, key);

        signer.update(signedData.encode());
        byte[] signature = signer.sign();

        signedData.setSignature(signature);
    }

    public static boolean verify(SignedData signedData, Certificate certificate) {
        return verify(signedData, certificate.getPublicKey());
    }

    @SneakyThrows(SignatureException.class)
    public static boolean verify(SignedData signedData, RSAPublicKey key) {
        Signature verifier = getInstance();
        initVerify(verifier, key);

        verifier.update(signedData.encode());
        byte[] signature = signedData.getSignature();

        return verifier.verify(signature);
    }

    @SneakyThrows
    private static Signature getInstance() {
        return Signature.getInstance(HASH_ALGORITHM + "WithRSA", "BC");
    }

    @SneakyThrows
    private static void initSign(Signature signature, RSAPrivateKey privateKey) {
        BigInteger n = privateKey.getN();
        BigInteger d = privateKey.getD();

        PrivateKey key = getKeyFactory().generatePrivate(new RSAPrivateKeySpec(n, d));
        signature.initSign(key);
    }

    @SneakyThrows
    private static void initVerify(Signature signature, RSAPublicKey publicKey) {
        BigInteger n = publicKey.getN();
        BigInteger e = publicKey.getE();

        PublicKey key = getKeyFactory().generatePublic(new RSAPublicKeySpec(n, e));
        signature.initVerify(key);
    }

    @SneakyThrows
    private static KeyFactory getKeyFactory() {
        return KeyFactory.getInstance("RSA", "BC");
    }
}
