package crypt.ssl.mac;

import crypt.ssl.digest.DigestFactory;
import crypt.ssl.digest.HashAlgorithm;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;

public abstract class MacFactory {

    private MacFactory() {
    }

    public static HMac createHmac(HashAlgorithm hash) {
        return new HMac(DigestFactory.createDigest(hash));
    }

    public static HMac createHmac(Digest digest) {
        return new HMac(digest);
    }
}
