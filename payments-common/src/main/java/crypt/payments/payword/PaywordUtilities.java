package crypt.payments.payword;

import crypt.payments.utils.HashAlgorithm;
import crypt.payments.utils.HashUtils;

import java.util.Arrays;
import java.util.Random;

public abstract class PaywordUtilities {

    public static final String PAYWORD_HASH = HashAlgorithm.SHA1.getValue();

    private PaywordUtilities() {
    }

    public static byte[][] createPaywordChain(String hashAlgorithm, int length) {
        return createPaywordChain(hashAlgorithm, new Random(), length);
    }

    public static byte[][] createPaywordChain(String hashAlgorithm, Random random, int length) {
        int hashLength = HashUtils.hashLength(hashAlgorithm);
        byte[][] chain = new byte[length + 1][];

        // 1. First payword
        chain[length] = new byte[hashLength];
        random.nextBytes(chain[length]);

        // 2. Rest of the payword along with the root
        for (int i = length - 1; i >= 0; i--) {
            chain[i] = HashUtils.hash(hashAlgorithm, chain[i + 1]);
        }

        return chain;
    }

    public static boolean verifyPayment(String hashAlgorithm, byte[] root, Payment nextPayment) {
        return verifyPayment(hashAlgorithm, new Payment(0, root), nextPayment);
    }

    public static boolean verifyPayment(String hashAlgorithm, Payment prevPayment, Payment nextPayment) {
        final int prevIndex = prevPayment.getIndex();
        final int nextIndex = nextPayment.getIndex();

        final byte[] prevPayword = prevPayment.getPayword();
        byte[] nextPayword = nextPayment.getPayword();

        final int hashIterations = nextIndex - prevIndex;

        for (int i = 0; i < hashIterations; i++) {
            nextPayword = HashUtils.hash(hashAlgorithm, nextPayword);
        }

        return Arrays.equals(prevPayword, nextPayword);
    }
}
