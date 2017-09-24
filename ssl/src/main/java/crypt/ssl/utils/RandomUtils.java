package crypt.ssl.utils;

import java.util.Random;

public abstract class RandomUtils {

    private RandomUtils() {
    }

    public static byte[] getBytes(Random random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);

        return bytes;
    }
}
