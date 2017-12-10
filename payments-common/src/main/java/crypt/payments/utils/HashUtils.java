package crypt.payments.utils;

import lombok.SneakyThrows;

import java.security.MessageDigest;

public abstract class HashUtils {

    private HashUtils() {
    }

    public static byte[] hash(String algorithm, byte[] data) {
        return getDigest(algorithm).digest(data);
    }

    public static int hashLength(String algorithm) {
        return getDigest(algorithm).getDigestLength();
    }

    @SneakyThrows
    private static MessageDigest getDigest(String algorithm) {
        return MessageDigest.getInstance(algorithm, "BC");
    }
}
