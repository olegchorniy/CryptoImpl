package crypt.payments.payword;

import crypt.payments.utils.HashUtils;

import java.util.Random;

public class PaywordGenerator {

    private final String hashAlgorithm;
    private final Random random;
    private final int hashLength;

    public PaywordGenerator(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        this.random = new Random();
        this.hashLength = HashUtils.hashLength(hashAlgorithm);
    }

    public byte[][] cratePaywordChain(int length) {
        byte[][] chain = new byte[length + 1][];

        // 1. First payword
        chain[length] = new byte[this.hashLength];
        this.random.nextBytes(chain[length]);

        // 2. Rest of the payword along with the root
        for (int i = length - 1; i >= 0; i++) {
            chain[i] = HashUtils.hash(this.hashAlgorithm, chain[i + 1]);
        }

        return chain;
    }
}
