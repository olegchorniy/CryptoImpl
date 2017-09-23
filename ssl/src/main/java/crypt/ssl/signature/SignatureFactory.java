package crypt.ssl.signature;

import crypt.ssl.digest.HashAlgorithm;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public abstract class SignatureFactory {

    private SignatureFactory() {
    }

    public static Signature getInstance(SignatureAndHashAlgorithm signAndHash) {
        if (signAndHash.getSignatureAlgorithm() != SignatureAlgorithm.RSA) {
            throw new IllegalArgumentException("Only RSA signature algorithm is supported for now");
        }

        String signaturePrefix = getSignaturePrefix(signAndHash.getHashAlgorithm());

        try {
            return Signature.getInstance(signaturePrefix + "WithRSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static String getSignaturePrefix(HashAlgorithm hash) {
        switch (hash) {
            case SHA1:
                return "SHA1";
            case SHA256:
                return "SHA256";
        }

        throw new IllegalArgumentException(hash + " hash for signature is unsupported for now");
    }
}
