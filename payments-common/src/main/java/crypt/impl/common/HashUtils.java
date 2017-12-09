package crypt.impl.common;

import lombok.SneakyThrows;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public abstract class HashUtils {

    private HashUtils() {
    }

    public static byte[] hash(String algorithm, byte[] data) {
        return getDigest(algorithm).digest(data);
    }

    @SneakyThrows({NoSuchAlgorithmException.class, NoSuchProviderException.class})
    private static MessageDigest getDigest(String algorithm) {
        return MessageDigest.getInstance(algorithm, "BC");
    }
}
