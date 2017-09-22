package crypt.ssl.digest;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public abstract class DigestFactory {

    public static Digest createDigest(HashAlgorithm algorithm) {
        switch (algorithm) {
            case SHA1:
                return new SHA1Digest();
            case SHA256:
                return new SHA256Digest();
        }

        throw new IllegalStateException(algorithm + " digest is not supported");
    }
}
