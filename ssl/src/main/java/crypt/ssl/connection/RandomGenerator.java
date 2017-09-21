package crypt.ssl.connection;

import java.util.Random;

public class RandomGenerator {

    private final Random delegate;

    public RandomGenerator(Random delegate) {
        this.delegate = delegate;
    }

    public int randomInt() {
        return delegate.nextInt();
    }

    public byte[] getBytes(int length) {
        byte[] bytes = new byte[length];
        delegate.nextBytes(bytes);

        return bytes;
    }
}
