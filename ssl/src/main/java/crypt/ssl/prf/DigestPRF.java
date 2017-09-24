package crypt.ssl.prf;

import crypt.ssl.digest.DigestFactory;
import crypt.ssl.digest.HashAlgorithm;
import crypt.ssl.mac.MacFactory;
import crypt.ssl.utils.Bits;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;

public class DigestPRF implements PRF {

    private final HMac hMac;

    public DigestPRF(HashAlgorithm hash) {
        this(DigestFactory.createDigest(hash));
    }

    public DigestPRF(Digest digest) {
        this.hMac = MacFactory.createHmac(digest);
    }

    /*
    A(0) = seed
    A(i) = HMAC_hash(secret, A(i-1))

    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                           HMAC_hash(secret, A(2) + seed) +
                           HMAC_hash(secret, A(3) + seed) + ...

    PRF(secret, label, seed) = P_hash(secret, label + seed)
                             = HMAC_hash(secret, A(1) + label + seed) +
                               HMAC_hash(secret, A(2) + label + seed) +
                               HMAC_hash(secret, A(3) + label + seed) + ...
    */

    @Override
    public byte[] compute(byte[] secret, String asciiLabel, byte[] seed, int outputLength) {
        this.hMac.init(new KeyParameter(secret));

        final int macSize = hMac.getMacSize();
        final byte[] label = asciiLabel.getBytes(StandardCharsets.US_ASCII);
        final byte[] prfSeed = Bits.concat(label, seed);

        byte[] a = prfSeed;

        int outputOffset = 0;
        byte[] output = new byte[outputLength];

        while (outputOffset != outputLength) {
            a = hmac(a);
            byte[] prfPart = hmac(a, prfSeed);

            int copyLength = Math.min(macSize, outputLength - outputOffset);
            System.arraycopy(prfPart, 0, output, outputOffset, copyLength);
            outputOffset += copyLength;
        }

        return output;
    }

    private byte[] hmac(byte[]... data) {
        for (byte[] input : data) {
            this.hMac.update(input, 0, input.length);
        }

        byte[] hmacOut = new byte[this.hMac.getMacSize()];
        this.hMac.doFinal(hmacOut, 0);

        return hmacOut;
    }
}
